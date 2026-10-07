"""SSH Fixup Engine - run operator-supplied CLI commands over SSH (netmiko) on many devices.

The job embeds no vendor commands. The operator pastes the command list into the form,
picks devices and a Secrets Group, and the job logs ``sending: ...`` / ``response: ...``
for every command on every device, attaching a transcript and a results file per run.

The netmiko mechanics live in :mod:`.ssh_runner` (no Nautobot imports) so they can be
tested against a fake SSH server without a database.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

import jinja2
from celery.exceptions import SoftTimeLimitExceeded
from django import forms
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from jinja2.sandbox import ImmutableSandboxedEnvironment
from nautobot.apps.jobs import (
    BooleanVar,
    ChoiceVar,
    DryRunVar,
    IntegerVar,
    Job,
    MultiObjectVar,
    ObjectVar,
    RunJobTaskFailed,
    StringVar,
    TextVar,
)
from nautobot.dcim.models import Device
from nautobot.extras.choices import SecretsGroupAccessTypeChoices, SecretsGroupSecretTypeChoices
from nautobot.extras.constants import JOB_LOG_MAX_GROUPING_LENGTH
from nautobot.extras.models import DynamicGroup, Secret, SecretsGroup, SecretsGroupAssociation, Tag
from nautobot.extras.secrets.exceptions import SecretError
from netmiko.ssh_dispatcher import CLASS_MAPPER_BASE as NETMIKO_BASE_TYPES

from .ssh_runner import (
    GENERIC_DEVICE_TYPE,
    SessionLogger,
    SessionResult,
    SessionSpec,
    environment_summary,
    normalise_commands,
    resolve_device_type,
    run_session,
    verify_login,
)

name = "Fixups"  # Job grouping shown in the Nautobot UI

#: Manufacturer / platform name fragments that select netmiko's ``apc_aos`` driver when
#: no explicit device_type is given and the Platform has no netmiko mapping.
APC_NAME_HINTS = ("apc", "schneider")
APC_DEVICE_TYPE = "apc_aos"
CREDENTIAL_ACCESS_TYPES = (SecretsGroupAccessTypeChoices.TYPE_GENERIC, SecretsGroupAccessTypeChoices.TYPE_SSH)
#: Command fragments that usually carry a literal credential; the job warns when it sees them
#: without the ``secret()`` helper (the job inputs are stored with the Job Result).
CREDENTIAL_HINTS = re.compile(r"(^|\s)(-pw|-cp)\s+\S|password|passwd|secret", re.IGNORECASE)
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
NON_NEGATIVE = forms.NumberInput(attrs={"min": 0})  # Nautobot drops IntegerVar(min_value=0); the widget still helps
ACTIVE_STATUS_NAME = "active"

DEVICE_TYPE_CHOICES = [("", "Auto (Platform netmiko driver, else apc_aos for APC/Schneider, else generic)")] + [
    (driver, driver) for driver in sorted(NETMIKO_BASE_TYPES)
]
SEND_METHOD_CHOICES = (
    ("prompt", "Wait for the CLI prompt after each command (recommended)"),
    ("timing", "Wait for output to go quiet (for CLIs without a stable prompt, or reboot/YES)"),
)


def _grouping(device) -> str:
    """Per-device log grouping; the column is capped at JOB_LOG_MAX_GROUPING_LENGTH characters."""
    return (device.name or str(device.pk))[:JOB_LOG_MAX_GROUPING_LENGTH]


def _code(text: str) -> str:
    """Format text as Markdown code so the UI shows it verbatim (``*name*`` must not become italics)."""
    if "\n" in text:
        fence = "````" if "```" in text else "```"
        return f"\n{fence}\n{text}\n{fence}"
    return f"`{text}`" if "`" not in text else text


def _mask(text: str, pattern: str | None) -> str:
    return re.sub(pattern, "****", text, flags=re.IGNORECASE | re.MULTILINE) if pattern else text


class _JobSessionLogger(SessionLogger):
    """Routes runner messages into the Nautobot job log, grouped per device, Markdown-formatted."""

    def __init__(self, logger, device):
        self.logger = logger
        self.extra = {"object": device, "grouping": _grouping(device)}

    def debug(self, msg: str) -> None:
        self.logger.debug("%s", msg, extra=self.extra)

    def info(self, msg: str) -> None:
        self.logger.info("%s", msg, extra=self.extra)

    def warning(self, msg: str) -> None:
        self.logger.warning("%s", msg, extra=self.extra)

    def error(self, msg: str) -> None:
        self.logger.error("%s", msg, extra=self.extra)

    def sending(self, command: str) -> None:
        self.info(f"sending: {_code(command)}")

    def response(self, command: str, text: str, ok: bool = True, warn: bool = False) -> None:
        emit = self.error if not ok else (self.warning if warn else self.info)
        emit(f"response: {_code(text)}")


def _build_jinja_env() -> jinja2.Environment:
    """Jinja2 environment for command templates: strict about undefined names, Nautobot filters available."""
    # sandboxed: templates can read device attributes but cannot call save()/delete(), reach _meta or
    # walk the ORM to other objects' secrets
    env = ImmutableSandboxedEnvironment(undefined=jinja2.StrictUndefined, autoescape=False)
    try:
        from django.template import engines

        env.filters.update(engines["jinja"].env.filters)  # netutils + Nautobot filters
    except Exception:  # filters are a convenience, never a hard requirement
        pass
    return env


@dataclass
class _Plan:
    """Everything resolved for one device during pre-flight (no network I/O)."""

    device: object
    host: str = ""
    device_type: str = ""
    type_reason: str = ""
    secrets_group_name: str = ""
    commands: list[str] = field(default_factory=list)
    display: list[str] = field(default_factory=list)
    secret_values: list[str] = field(default_factory=list)
    skip: str = ""  # non-empty = do not attempt (reason)


class SSHFixupEngine(Job):
    """Run a pasted list of CLI commands over SSH on the selected devices, one command at a time."""

    # ---- target selection
    devices = MultiObjectVar(
        model=Device,
        required=False,
        description="Explicit devices to run against. Combined (union) with the tags and dynamic groups below.",
    )
    tags = MultiObjectVar(
        model=Tag,
        required=False,
        query_params={"content_types": "dcim.device"},
        description="Also include every device carrying any of these tags.",
    )
    dynamic_groups = MultiObjectVar(
        model=DynamicGroup,
        required=False,
        query_params={"content_type": "dcim.device"},
        description="Also include the members of these Device dynamic groups (membership as last cached by Nautobot).",
    )
    include_non_active = BooleanVar(
        label="Include non-Active devices",
        default=False,
        description="By default devices whose Status is not 'Active' are listed as skipped, not touched.",
    )
    max_devices = IntegerVar(
        label="Maximum devices",
        default=50,
        min_value=1,
        max_value=10000,
        description="Blast-radius guard: refuse to start if the selection resolves to more devices than this.",
    )
    canary_count = IntegerVar(
        label="Canary devices",
        default=1,
        min_value=0,
        widget=NON_NEGATIVE,
        max_value=100,
        description=(
            "Run this many devices (in name order) first; if any of them fails, stop before touching the rest. "
            "0 disables."
        ),
    )
    max_device_failures = IntegerVar(
        label="Abort after N failed devices",
        default=3,
        min_value=0,
        widget=NON_NEGATIVE,
        max_value=10000,
        description="Circuit breaker: stop the run once this many devices have failed (0 = never stop).",
    )
    change_reference = StringVar(
        label="Change reference",
        required=False,
        description="Ticket / change number, recorded in the log header and the results file.",
    )

    # ---- credentials
    secrets_group = ObjectVar(
        model=SecretsGroup,
        required=False,
        description=(
            "Secrets Group holding the SSH username and password (access type 'Generic' or 'SSH'; "
            "an optional 'secret' is used as the enable secret). "
            "Leave blank to use each device's own Secrets Group."
        ),
    )

    # ---- what to send
    commands = TextVar(
        label="Commands",
        description=(
            "One CLI command per line, sent in order. Blank lines and lines starting with #, ! or // are ignored. "
            "Lines are Jinja2 templates when 'Render with Jinja2' is on, e.g. "
            "Email -f1 {{ device.name }}@example.local"
        ),
    )
    render_jinja = BooleanVar(
        label="Render with Jinja2",
        default=True,
        description=(
            "Render each line as a Jinja2 template before sending. Available: device (the Nautobot Device), "
            "obj (alias), secret('Nautobot Secret name') to insert a secret value without storing it in the job "
            "inputs or showing it in the log, plus Nautobot/netutils filters. Undefined names fail the run "
            "before anything is sent."
        ),
    )
    deny_pattern = StringVar(
        label="Deny pattern (regex)",
        required=False,
        description=(
            "Safety net: refuse the whole run if any rendered command matches this regex. Example for APC: "
            r"^(reboot|resetToDef|format|user|console)\b|^tcpip\b.*\s-(i|s|g)\b  (session-ending or lock-out commands)."
        ),
    )
    mask_pattern = StringVar(
        label="Mask pattern (regex)",
        required=False,
        description=(
            "Anything matching this regex is replaced with **** in the job log and transcript files, e.g. "
            r"(?<=-s1 )\S+ to hide a RADIUS shared secret typed directly into a command. "
            "Note: job inputs themselves are still stored verbatim; prefer the secret() helper."
        ),
    )
    pause_seconds = IntegerVar(
        label="Pause between commands (seconds)",
        default=1,
        min_value=0,
        widget=NON_NEGATIVE,
        max_value=120,
        description="Sleep this long after each response before sending the next command.",
    )
    command_timeout = IntegerVar(
        label="Command timeout (seconds)",
        default=30,
        min_value=1,
        max_value=600,
        description="Give up waiting for a command's response after this long.",
    )
    conn_timeout = IntegerVar(
        label="Connection timeout (seconds)",
        default=15,
        min_value=1,
        max_value=120,
        description="TCP connect timeout; SSH banner and authentication get twice this (minimum 30 s).",
    )
    connect_retries = IntegerVar(
        label="Connection retries",
        default=1,
        min_value=0,
        widget=NON_NEGATIVE,
        max_value=5,
        description=(
            "Extra connection attempts (5 s backoff, doubling) on timeouts or a missing prompt. Never on auth failures."
        ),
    )
    known_hosts_file = StringVar(
        label="Known hosts file",
        required=False,
        description=(
            "Path on the worker to an OpenSSH known_hosts file. When set, connections to unknown or changed host "
            "keys are refused. Blank (default) accepts any host key, as netmiko does."
        ),
    )
    ssh_port = IntegerVar(
        label="SSH port",
        default=22,
        min_value=1,
        max_value=65535,
        description="TCP port for SSH on every selected device.",
    )

    # ---- how to talk to the device
    netmiko_device_type = ChoiceVar(
        label="Netmiko device type",
        choices=DEVICE_TYPE_CHOICES,
        default="",
        required=False,
        description=(
            "Netmiko driver. 'Auto' uses the device Platform's netmiko network driver when one is mapped. "
            "A selection that resolves to more than one driver is refused unless you pick one explicitly."
        ),
    )
    send_method = ChoiceVar(
        label="Send method",
        choices=SEND_METHOD_CHOICES,
        default="prompt",
        description=(
            "How netmiko decides a command has finished. 'prompt' accepts the login prompt in any mode "
            "(Switch#, Switch(config)#, [root@esxi:~]); 'timing' waits for output to stop."
        ),
    )
    prompt_pattern = StringVar(
        label="Prompt pattern (regex)",
        required=False,
        description=(
            "Only for the 'prompt' send method: regex that means 'the prompt is back'. Leave blank to derive it from "
            r"the prompt seen at login. Needed when commands change the prompt text itself, e.g. cd on ESXi/Linux: "
            r"\[root@\S+\] $  or  root@\S+#\s*$"
        ),
    )
    error_pattern = StringVar(
        label="Error pattern (regex)",
        required=False,
        description=(
            "Responses matching this regular expression (case-insensitive, multi-line) are logged as errors. "
            r"Example for APC NMC: ^E1\d{2}:  (E100-E108 are failures; E000/E001 mean success, E002 means "
            "success but reboot required)."
        ),
    )
    success_pattern = StringVar(
        label="Success pattern (regex)",
        required=False,
        description=(
            "Responses NOT matching this regular expression are logged as errors (checked after the error pattern). "
            r"Example for APC NMC: ^E00[012]:  Catches wrong platforms and empty responses."
        ),
    )
    warning_pattern = StringVar(
        label="Warning pattern (regex)",
        required=False,
        description=(
            "Responses matching this regular expression are logged as warnings (the command still counts as OK). "
            r"Example for APC NMC: ^E002:  (reboot required for the change to take effect)."
        ),
    )
    stop_on_error = BooleanVar(
        label="Stop device on error",
        default=True,
        description="After an error response or timeout, send no further commands to that device.",
    )
    disconnect_ok_on_last_command = BooleanVar(
        label="Dropped connection after the last command is OK",
        default=False,
        description=(
            "Tick when the final command reboots the device or closes the session, e.g. APC 'reboot' followed by "
            "'YES' with the 'timing' send method. The drop is then logged as expected instead of as a failure."
        ),
    )
    verify_relogin = BooleanVar(
        label="Verify re-login afterwards",
        default=True,
        description=(
            "After the commands, log in once more with the same credentials and fail the device if that no longer "
            "works (catches RADIUS/user/console changes that lock you out while answering 'Success'). Skipped on dry "
            "runs and when 'Dropped connection after the last command is OK' is ticked."
        ),
    )
    enter_enable_mode = BooleanVar(
        label="Enter enable mode first",
        default=False,
        description="Call netmiko enable() after login (Cisco-style platforms). Not needed for APC.",
    )
    logout_command = StringVar(
        label="Logout command",
        required=False,
        default="exit",
        description=(
            "Command written just before disconnecting so the device frees the session slot. Blank sends nothing."
        ),
    )
    attach_files = BooleanVar(
        label="Attach transcript and results files",
        default=True,
        description=(
            "Attach ssh-fixup-transcript.txt (verbatim sending/response transcript plus raw SSH session logs for "
            "every device) and ssh-fixup-results.json to the Job Result."
        ),
    )
    dryrun = DryRunVar(
        description=(
            "Connect to each device, detect the prompt and log the commands that WOULD be sent. Sends nothing. "
            "Untick to run for real."
        )
    )

    class Meta:
        name = "SSH Fixup Engine"
        description = (
            "Log in to each selected device over SSH (netmiko) and run a pasted list of CLI commands one at a time, "
            "logging 'sending:' / 'response:' pairs. Credentials come from a Secrets Group only."
        )
        has_sensitive_variables = False  # inputs are plain CLI text; credentials never pass through the form
        approval_required = False  # enable per deployment on the Job model if you want a two-person rule
        dryrun_default = True  # a fleet-wide change tool should be safe on the first click
        soft_time_limit = 3600  # a fleet of slow management cards can take a while; Nautobot's default is 5 minutes
        time_limit = 3900
        field_order = [
            "devices",
            "tags",
            "dynamic_groups",
            "include_non_active",
            "max_devices",
            "canary_count",
            "max_device_failures",
            "change_reference",
            "secrets_group",
            "commands",
            "render_jinja",
            "deny_pattern",
            "mask_pattern",
            "pause_seconds",
            "command_timeout",
            "conn_timeout",
            "connect_retries",
            "known_hosts_file",
            "ssh_port",
            "netmiko_device_type",
            "send_method",
            "prompt_pattern",
            "error_pattern",
            "success_pattern",
            "warning_pattern",
            "stop_on_error",
            "disconnect_ok_on_last_command",
            "verify_relogin",
            "enter_enable_mode",
            "logout_command",
            "attach_files",
            "dryrun",
        ]

    # ------------------------------------------------------------------ pre-flight helpers

    @staticmethod
    def _select_devices(devices, tags, dynamic_groups):
        """Union of explicit devices, devices with any of the tags, and dynamic group members."""
        selected = {device.pk: device for device in devices} if devices else {}
        if tags:
            for device in Device.objects.filter(tags__in=list(tags)).distinct():
                selected.setdefault(device.pk, device)
        for group in dynamic_groups or []:
            for device in group.members:
                selected.setdefault(device.pk, device)
        return sorted(selected.values(), key=lambda d: (d.name or "", str(d.pk)))

    @staticmethod
    def _check_secrets_group(group) -> None:
        """Fail fast if the job-level SecretsGroup cannot yield a username + password under one access type."""
        for access_type in CREDENTIAL_ACCESS_TYPES:
            associations = SecretsGroupAssociation.objects.filter(secrets_group=group, access_type=access_type)
            has_user = associations.filter(secret_type=SecretsGroupSecretTypeChoices.TYPE_USERNAME).exists()
            has_pass = associations.filter(secret_type=SecretsGroupSecretTypeChoices.TYPE_PASSWORD).exists()
            if has_user and has_pass:
                return
        # (wording avoids "secret <word>" / "password <word>", which Nautobot's log sanitizer would redact)
        raise RunJobTaskFailed(
            f"SecretsGroup '{group}' lacks a username+password pair under one access type (Generic or SSH)."
        )

    @staticmethod
    def _resolve_credentials(device, secrets_group):
        """Return (username, password, secret, access_type) from the job-level or device-level Secrets Group."""
        group = secrets_group or device.secrets_group
        if group is None:
            raise LookupError("no SecretsGroup selected on the job and none assigned to the device")
        for access_type in CREDENTIAL_ACCESS_TYPES:
            try:
                username = group.get_secret_value(
                    access_type=access_type, secret_type=SecretsGroupSecretTypeChoices.TYPE_USERNAME, obj=device
                )
                password = group.get_secret_value(
                    access_type=access_type, secret_type=SecretsGroupSecretTypeChoices.TYPE_PASSWORD, obj=device
                )
            except ObjectDoesNotExist:
                continue
            try:
                secret = group.get_secret_value(
                    access_type=access_type, secret_type=SecretsGroupSecretTypeChoices.TYPE_SECRET, obj=device
                )
            except ObjectDoesNotExist:
                secret = ""
            return username, password, secret or "", access_type
        raise LookupError(f"SecretsGroup '{group}' lacks a username+password pair under one access type (Generic/SSH)")

    @staticmethod
    def _resolve_device_type(device, requested: str):
        """Explicit choice > Platform netmiko mapping > APC manufacturer hint > generic. Returns (type, reason)."""
        requested = (requested or "").strip()
        if requested:
            return resolve_device_type(requested), "job field"
        platform = device.platform
        if platform is not None:
            mapped = (platform.network_driver_mappings or {}).get("netmiko")
            if mapped:
                return resolve_device_type("", mapped), f"platform '{platform}' netmiko mapping"
        names = [
            platform.name if platform else "",
            platform.manufacturer.name if platform and platform.manufacturer else "",
        ]
        if device.device_type is not None and device.device_type.manufacturer is not None:
            names.append(device.device_type.manufacturer.name)
        haystack = " ".join(n for n in names if n).lower()
        if any(hint in haystack for hint in APC_NAME_HINTS):
            return resolve_device_type("", APC_DEVICE_TYPE), "APC/Schneider manufacturer or platform name"
        return GENERIC_DEVICE_TYPE, "fallback (no platform mapping)"

    def _render_commands(self, env, commands, device, mask_pattern=None):
        """Render each line for one device.

        Returns (rendered, display, secret_values): ``display`` shows the unrendered template for lines that
        used the ``secret()`` helper so secret values never reach the job log.
        """
        secret_values: list[str] = []
        used_secret = False
        user = getattr(self, "user", None)

        def secret(secret_name: str) -> str:
            nonlocal used_secret
            queryset = Secret.objects.all()
            if user is not None:  # only Secrets the running user may view
                queryset = queryset.restrict(user, "view")
            try:
                value = queryset.get(name=secret_name).get_value(obj=device)
            except Secret.DoesNotExist:
                raise ValueError(f"secret('{secret_name}'): no Nautobot Secret with that name that you may view")
            used_secret = True
            if value:
                secret_values.append(str(value))
            return str(value)

        context = {"device": device, "obj": device, "secret": secret}
        rendered: list[str] = []
        display: list[str] = []
        for line in commands:
            if "{{" not in line and "{%" not in line and "{#" not in line:
                rendered.append(line)
                display.append(line)
                continue
            used_secret = False
            shown_line = _mask(line, mask_pattern)
            try:
                out = env.from_string(line).render(context).strip()
            except jinja2.UndefinedError as exc:
                raise ValueError(f"undefined name in template {shown_line!r}: {exc}")
            except jinja2.TemplateError as exc:
                raise ValueError(f"template error in {shown_line!r}: {exc}")
            if CONTROL_CHARS.search(out):
                # a CR/LF smuggled in through a device field would become a second command the deny
                # pattern never saw
                raise ValueError(f"template {shown_line!r} rendered to text containing control characters")
            if out:
                rendered.append(out)
                display.append(line if used_secret else out)
        return rendered, display, secret_values

    def _preflight(
        self,
        targets,
        *,
        include_non_active,
        secrets_group,
        netmiko_device_type,
        env,
        command_list,
        deny_re,
        mask_pattern,
    ):
        """Resolve everything for every device before any connection. Raises RunJobTaskFailed on fatal problems."""
        plans: list[_Plan] = []
        fatal: list[str] = []
        for device in targets:
            plan = _Plan(device=device)
            plans.append(plan)
            status_name = (getattr(device.status, "name", "") or "").lower()
            if not include_non_active and status_name != ACTIVE_STATUS_NAME:
                plan.skip = f"status is '{device.status}' (tick 'Include non-Active devices' to include it)"
                continue
            ip = device.primary_ip  # honours the PREFER_IPV4 setting
            if ip is None:
                plan.skip = "no primary IP address set in Nautobot"
                continue
            plan.host = str(ip.host)
            try:
                plan.device_type, plan.type_reason = self._resolve_device_type(device, netmiko_device_type)
            except ValueError as exc:
                fatal.append(f"{device}: {exc}")
                continue
            group = secrets_group or device.secrets_group
            if group is None:
                plan.skip = "no SecretsGroup selected on the job and none assigned to the device"
                continue
            plan.secrets_group_name = str(group)
            try:
                if env is not None:
                    plan.commands, plan.display, plan.secret_values = self._render_commands(
                        env, command_list, device, mask_pattern
                    )
                else:
                    plan.commands, plan.display = list(command_list), list(command_list)
            except (ValueError, SecretError) as exc:
                fatal.append(f"{device}: {exc}")
                continue
            if not plan.commands:
                fatal.append(f"{device}: all commands rendered to empty strings")
                continue
            if deny_re is not None:
                for number, (line, shown) in enumerate(zip(plan.commands, plan.display), start=1):
                    if deny_re.search(line):
                        fatal.append(
                            f"{device}: command {number} ({_mask(shown, mask_pattern)!r}) matches the deny pattern"
                        )
                        break
        if fatal:
            shown = "\n".join(f"- {f}" for f in fatal[:20]) + ("\n- ..." if len(fatal) > 20 else "")
            raise RunJobTaskFailed(f"Pre-flight failed for {len(fatal)} device(s); nothing was sent:\n{shown}")
        active = [p for p in plans if not p.skip]
        if not (netmiko_device_type or "").strip():
            kinds = sorted({p.device_type for p in active})
            if len(kinds) > 1:
                raise RunJobTaskFailed(
                    f"Selection resolves to more than one netmiko driver ({', '.join(kinds)}); this usually means the "
                    "selection caught the wrong platform. Narrow it or set 'Netmiko device type' explicitly."
                )
        return plans

    def _attach(self, filename: str, content: str) -> None:
        try:
            self.create_file(filename, content)
        except Exception as exc:  # never fail the run because of an attachment
            self.logger.warning("could not attach %s: %s", filename, exc, extra={"grouping": "summary"})

    # ------------------------------------------------------------------ run

    def run(
        self,
        *,
        devices,
        tags,
        dynamic_groups,
        include_non_active,
        max_devices,
        canary_count,
        max_device_failures,
        change_reference,
        secrets_group,
        commands,
        render_jinja,
        deny_pattern,
        mask_pattern,
        pause_seconds,
        command_timeout,
        conn_timeout,
        connect_retries,
        known_hosts_file,
        ssh_port,
        netmiko_device_type,
        send_method,
        prompt_pattern,
        error_pattern,
        success_pattern,
        warning_pattern,
        stop_on_error,
        disconnect_ok_on_last_command,
        verify_relogin,
        enter_enable_mode,
        logout_command,
        attach_files,
        dryrun,
    ):
        setup = {"grouping": "setup"}
        # ---- 1. cheap validation before any network I/O
        command_list, notes = normalise_commands(commands or "")
        if not command_list:
            raise RunJobTaskFailed("No commands given (blank lines and comment lines are ignored).")
        for label, value in (
            ("Pause between commands", pause_seconds),
            ("Canary devices", canary_count),
            ("Abort after N failed devices", max_device_failures),
            ("Connection retries", connect_retries),
        ):
            if value is None or value < 0:  # Nautobot ignores IntegerVar(min_value=0), so check here
                raise RunJobTaskFailed(f"'{label}' must be 0 or more.")
        # the limit Nautobot actually enforces (Job model override > settings > class default)
        job_model = getattr(self, "job_model", None)
        soft_limit = (
            getattr(job_model, "soft_time_limit", 0)
            or getattr(settings, "CELERY_TASK_SOFT_TIME_LIMIT", 0)
            or self.soft_time_limit
        )
        compiled = {}
        for label, pattern in (
            ("error", error_pattern),
            ("success", success_pattern),
            ("warning", warning_pattern),
            ("mask", mask_pattern),
            ("deny", deny_pattern),
            ("prompt", prompt_pattern),
        ):
            if pattern:
                try:
                    compiled[label] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                except re.error as exc:
                    raise RunJobTaskFailed(f"Invalid {label} pattern regex {pattern!r}: {exc}")
        if (netmiko_device_type or "").strip():
            resolve_device_type(netmiko_device_type)  # raises ValueError with a hint for unknown drivers
        if secrets_group is not None:
            self._check_secrets_group(secrets_group)

        targets = self._select_devices(devices, tags, dynamic_groups)
        if not targets:
            raise RunJobTaskFailed("No devices selected. Pick devices, tags and/or dynamic groups.")
        if len(targets) > max_devices:
            raise RunJobTaskFailed(
                f"Selection resolved to {len(targets)} devices but 'Maximum devices' is {max_devices}. "
                "Raise the limit deliberately or narrow the selection."
            )

        mode = "DRY RUN - nothing will be sent" if dryrun else "LIVE"
        digest = hashlib.sha256("\n".join(command_list).encode()).hexdigest()[:12]
        self.logger.info(
            "%s: %d command(s) on %d device(s)%s | pause=%ss command_timeout=%ss conn_timeout=%ss retries=%s "
            "send_method=%s port=%s canary=%s max_failures=%s max_devices=%s | commands sha256 %s",
            mode,
            len(command_list),
            len(targets),
            f" | change {change_reference}" if change_reference else "",
            pause_seconds,
            command_timeout,
            conn_timeout,
            connect_retries,
            send_method,
            ssh_port,
            canary_count,
            max_device_failures,
            max_devices,
            digest,
            extra=setup,
        )
        self.logger.info("%s", environment_summary(), extra=setup)
        for note in notes:
            self.logger.warning("normalised %s", note, extra=setup)
        self.logger.info(
            "commands to send (before Jinja rendering):\n```\n%s\n```",
            _mask("\n".join(command_list), mask_pattern),
            extra=setup,
        )
        suspicious = [
            f"line {n}: {_mask(c, mask_pattern)}"
            for n, c in enumerate(command_list, start=1)
            if CREDENTIAL_HINTS.search(c) and "secret(" not in c
        ]
        if suspicious:
            self.logger.warning(
                "these command line(s) look like they carry a literal credential (ignore if not): %s. Job inputs are "
                "stored with the Job Result and published in job events. Prefer {{ secret('name') }} and/or a mask "
                "pattern.",
                "; ".join(suspicious),
                extra=setup,
            )
        worst_case = len(targets) * (
            (1 + connect_retries) * conn_timeout + len(command_list) * (command_timeout + pause_seconds)
        )
        if worst_case > soft_limit:
            self.logger.warning(
                "worst-case duration is %d s (every command timing out) but the job's soft time limit is %d s; "
                "consider fewer devices per run or shorter timeouts",
                worst_case,
                soft_limit,
                extra=setup,
            )

        # ---- 2. pre-flight: resolve hosts, drivers, credentials and templates for EVERY device first
        env = _build_jinja_env() if render_jinja else None
        plans = self._preflight(
            targets,
            include_non_active=include_non_active,
            secrets_group=secrets_group,
            netmiko_device_type=netmiko_device_type,
            env=env,
            command_list=command_list,
            deny_re=compiled.get("deny"),
            mask_pattern=mask_pattern,
        )
        rows = ["| # | Device | Host | Driver | Credentials | Commands | Note |", "|---|---|---|---|---|---|---|"]
        for index, plan in enumerate(plans, start=1):
            note = f"SKIP: {plan.skip}" if plan.skip else plan.type_reason
            rows.append(
                f"| {index} | {plan.device} | {plan.host or '-'} | {plan.device_type or '-'} | "
                f"{plan.secrets_group_name or '-'} | {len(plan.commands)} | {note.replace('|', '/')} |"
            )
        self.logger.info("plan:\n\n%s", "\n".join(rows), extra=setup)  # blank line so Markdown renders the table
        skipped = [p for p in plans if p.skip]
        if skipped:
            self.logger.warning("%d device(s) will be skipped (see plan)", len(skipped), extra=setup)
        if len(skipped) == len(plans):
            raise RunJobTaskFailed(
                f"All {len(plans)} selected device(s) would be skipped (see the plan); nothing to do."
            )

        # ---- 3. the fleet loop
        results: list[tuple[_Plan, SessionResult | None, str]] = []
        aborted = ""
        failures = 0
        try:
            for index, plan in enumerate(plans, start=1):
                device = plan.device
                extra = {"object": device, "grouping": _grouping(device)}
                if plan.skip:
                    self.logger.warning(
                        "device %d/%d: %s skipped: %s", index, len(plans), device, plan.skip, extra=extra
                    )
                    results.append((plan, None, f"skipped: {plan.skip}"))
                    continue
                self.logger.info("device %d/%d: %s", index, len(plans), device, extra=extra)
                self.logger.info("netmiko device_type %s (%s)", plan.device_type, plan.type_reason, extra=extra)
                same_length = len(plan.display) == len(command_list)
                changed = [d for c, d in zip(command_list, plan.display) if c != d] if same_length else plan.display
                if changed:
                    self.logger.info(
                        "rendered for this device:\n```\n%s\n```", _mask("\n".join(changed), mask_pattern), extra=extra
                    )
                failure = ""
                result: SessionResult | None = None
                try:
                    username, password, secret, access_type = self._resolve_credentials(device, secrets_group)
                    # (wording avoids Nautobot's log sanitizer, which redacts the token after the word "secrets")
                    self.logger.debug(
                        "credentials resolved via access type %s (user %s)", access_type, username, extra=extra
                    )
                    spec = SessionSpec(
                        host=plan.host,
                        port=int(ssh_port or 22),
                        username=username,
                        password=password,
                        secret=secret,
                        commands=plan.commands,
                        display_commands=plan.display,
                        mask_values=plan.secret_values,
                        mask_pattern=mask_pattern or None,
                        label=device.name or str(device.pk),
                        device_type=plan.device_type,
                        pause_seconds=float(pause_seconds or 0),
                        command_timeout=float(command_timeout),
                        conn_timeout=float(conn_timeout),
                        connect_retries=int(connect_retries or 0),
                        known_hosts_file=(known_hosts_file or "").strip() or None,
                        send_method=send_method or "prompt",
                        prompt_pattern=(prompt_pattern or "").strip() or None,
                        error_pattern=error_pattern or None,
                        success_pattern=success_pattern or None,
                        warning_pattern=warning_pattern or None,
                        stop_on_error=bool(stop_on_error),
                        disconnect_ok_on_last_command=bool(disconnect_ok_on_last_command),
                        enter_enable=bool(enter_enable_mode),
                        logout_command=(logout_command or "").strip(),
                        dry_run=bool(dryrun),
                    )
                    result = run_session(spec, _JobSessionLogger(self.logger, device))
                    if result.error:
                        failure = result.error
                    elif result.failed:
                        failure = f"{result.failed} of {result.sent} command(s) failed"
                    elif verify_relogin and not dryrun:
                        if disconnect_ok_on_last_command:
                            self.logger.info(
                                "re-login check skipped: the connection was expected to drop after the last command",
                                extra=extra,
                            )
                        else:
                            ok, error = verify_login(spec, _JobSessionLogger(self.logger, device))
                            if not ok:
                                failure = f"re-login after the changes failed: {error}"
                except SecretError as exc:
                    failure = f"could not retrieve credentials: {exc}"
                except (LookupError, ValueError) as exc:
                    failure = str(exc)
                except SoftTimeLimitExceeded:
                    results.append(
                        (plan, None, "interrupted: soft time limit reached while this device was in progress")
                    )
                    raise
                except Exception as exc:  # one broken device must not kill the fleet run
                    failure = f"unexpected error: {exc.__class__.__name__}: {exc}"

                results.append((plan, result, failure))
                attempted = sum(1 for _p, _r, f in results if not f.startswith("skipped:"))
                if failure:
                    failures += 1
                    self.logger.error("device %s FAILED: %s", device, failure, extra=extra)
                    remaining = len(plans) - index
                    if canary_count and attempted <= canary_count and remaining:
                        aborted = f"canary device {device} failed"
                        break
                    if max_device_failures and failures >= max_device_failures and remaining:
                        aborted = f"{failures} device(s) failed (limit {max_device_failures})"
                        break
                elif dryrun:
                    self.logger.success(
                        "device %s dry run OK (%d command(s) would be sent)", device, len(plan.commands), extra=extra
                    )
                else:
                    warned = result.warned if result else 0
                    self.logger.success(
                        "device %s OK (%d command(s)%s)",
                        device,
                        result.sent if result else 0,
                        f", {warned} warning(s)" if warned else "",
                        extra=extra,
                    )
        except SoftTimeLimitExceeded:
            aborted = f"soft time limit of {soft_limit} s reached"

        # ---- 4. summary, attachments, result
        summary_extra = {"grouping": "summary"}
        not_attempted = len(plans) - len(results)
        if aborted:
            self.logger.error("aborting: %s; %d device(s) not attempted", aborted, not_attempted, extra=summary_extra)
        failed = [(p, r, f) for p, r, f in results if f and not f.startswith("skipped:")]
        skipped_n = sum(1 for _p, _r, f in results if f.startswith("skipped:"))
        ok_n = len(results) - len(failed) - skipped_n
        rows = ["| Device | Host | Status | Sent | Failed | Warnings | Detail |", "|---|---|---|---|---|---|---|"]
        for plan, result, failure in results:
            if failure.startswith("skipped:"):
                status = "SKIPPED"
            elif failure.startswith("interrupted:"):
                status = "INTERRUPTED"
            elif failure:
                status = "FAILED"
            else:
                status = "DRY RUN" if dryrun else "OK"
            detail = failure or (f"prompt {result.prompt!r}" if result and result.prompt else "")
            rows.append(
                f"| {plan.device} | {plan.host or '-'} | {status} | {result.sent if result else 0} | "
                f"{result.failed if result else 0} | {result.warned if result else 0} | "
                f"{_mask(detail, mask_pattern).replace('|', '/')[:200]} |"
            )
        self.logger.info("\n\n%s", "\n".join(rows), extra=summary_extra)
        summary = (
            f"{mode}: {ok_n} OK, {len(failed)} failed, {skipped_n} skipped, {not_attempted} not attempted "
            f"(of {len(plans)} selected)"
        )
        outcome = {
            "mode": "dry-run" if dryrun else "live",
            "change_reference": change_reference or "",
            "commands_sha256": digest,
            "selected": len(plans),
            "ok": ok_n,
            "failed": len(failed),
            "skipped": skipped_n,
            "not_attempted": not_attempted,
            "aborted": aborted,
            "summary": summary,
            "devices": {},
        }
        for plan, result, failure in results:
            outcome["devices"][plan.device.name or str(plan.device.pk)] = {
                "pk": str(plan.device.pk),
                "host": plan.host,
                "driver": plan.device_type,
                "status": (
                    "skipped"
                    if failure.startswith("skipped:")
                    else "interrupted"
                    if failure.startswith("interrupted:")
                    else "failed"
                    if failure
                    else ("dry-run" if dryrun else "ok")
                ),
                "sent": result.sent if result else 0,
                "failed": result.failed if result else 0,
                "warnings": result.warned if result else 0,
                "prompt": result.prompt if result else "",
                "host_key": result.host_key if result else "",
                "duration": result.duration if result else 0,
                "detail": _mask(failure, mask_pattern),
            }
        for plan in plans[len(results) :]:
            outcome["devices"][plan.device.name or str(plan.device.pk)] = {
                "pk": str(plan.device.pk),
                "host": plan.host,
                "driver": plan.device_type,
                "status": "not_attempted",
                "detail": aborted,
            }
        if attach_files:
            transcript = "\n\n".join(
                f"{r.transcript}\n----- raw SSH session log -----\n{r.raw_session_log}" for _p, r, _f in results if r
            )
            header = f"SSH Fixup Engine {mode}" + (f" | change {change_reference}" if change_reference else "")
            self._attach("ssh-fixup-transcript.txt", f"{header}\ncommands sha256 {digest}\n\n{transcript}\n")
            self._attach("ssh-fixup-results.json", json.dumps(outcome, indent=2, default=str))
        if failed or aborted:
            self.fail("%s", summary, extra=summary_extra)
        else:
            self.logger.success("%s", summary, extra=summary_extra)
        return outcome
