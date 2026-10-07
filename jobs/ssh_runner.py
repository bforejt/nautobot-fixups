"""Vendor-agnostic netmiko session runner used by the SSH Fixup Engine job.

This module deliberately has **no Nautobot imports** so it can be exercised from a
plain shell or a unit test (see ``tests/``) against a fake SSH server. The Nautobot
job is a thin wrapper that resolves devices/credentials and feeds ``SessionSpec``
objects into :func:`run_session`.

The runner knows nothing about any particular vendor: the commands come from the
operator, the netmiko ``device_type`` selects the driver, and an optional regex
decides what counts as an error response.
"""

from __future__ import annotations

import base64
import hashlib
import io
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

import netmiko
import paramiko
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    ReadException,
    ReadTimeout,
)
from netmiko.ssh_dispatcher import CLASS_MAPPER as NETMIKO_CLASS_MAPPER
from paramiko.ssh_exception import SSHException

__all__ = [
    "DEFAULT_DEVICE_TYPE",
    "GENERIC_DEVICE_TYPE",
    "CommandResult",
    "PrintLogger",
    "SessionLogger",
    "SessionResult",
    "SessionSpec",
    "available_device_types",
    "environment_summary",
    "legacy_ssh_support",
    "normalise_commands",
    "parse_commands",
    "resolve_device_type",
    "run_session",
    "verify_login",
]

GENERIC_DEVICE_TYPE = "generic"
#: Preferred driver for APC Network Management Cards (netmiko >= 4.7). Falls back to
#: ``generic`` on older netmiko releases.
DEFAULT_DEVICE_TYPE = "apc_aos" if "apc_aos" in NETMIKO_CLASS_MAPPER else GENERIC_DEVICE_TYPE
COMMENT_PREFIXES = ("#", "!", "//")
SEND_METHODS = ("prompt", "timing")
NO_OUTPUT = "<no output>"


# --------------------------------------------------------------------------- data


@dataclass
class SessionSpec:
    """Everything needed to run one SSH session."""

    host: str
    username: str
    password: str = field(repr=False)
    commands: list[str] = field(default_factory=list)
    label: str = ""  # friendly name used in log lines (e.g. the Nautobot device name)
    device_type: str = DEFAULT_DEVICE_TYPE
    port: int = 22
    secret: str = field(default="", repr=False)  # enable secret, only used when ``enter_enable`` is set
    pause_seconds: float = 1.0  # pause between commands
    command_timeout: float = 30.0  # max seconds to wait for a response to one command
    conn_timeout: float = 15.0  # TCP / SSH banner / auth timeout
    send_method: str = "prompt"  # "prompt" (wait for prompt) or "timing" (wait for silence)
    error_pattern: str | None = None  # regex; a matching response is logged as an error
    success_pattern: str | None = None  # regex; a response NOT matching it is logged as an error
    warning_pattern: str | None = None  # regex; a matching response is logged as a warning (still ok)
    connect_retries: int = 1  # extra connection attempts on timeouts / missing prompt (never on auth failures)
    retry_backoff: float = 5.0  # seconds before the first retry; doubles each time
    stop_on_error: bool = True  # stop sending to this device after an error response
    disconnect_ok_on_last_command: bool = False  # e.g. the last command reboots the device
    enter_enable: bool = False
    logout_command: str = ""  # optional command written just before disconnect (e.g. "exit")
    disabled_algorithms: dict | None = None  # passed straight to paramiko (can only REMOVE algorithms)
    ssh_config_file: str | None = None  # netmiko only honours ProxyCommand/ProxyJump/Port/User/HostName from it
    known_hosts_file: str | None = None  # verify host keys against this file (netmiko ssh_strict); blank = accept any
    keepalive: int = 30  # SSH keepalive seconds; helps long command lists survive idle gaps
    global_delay_factor: float = 1.0
    dry_run: bool = False  # connect, detect the prompt, send nothing
    max_log_chars: int = 8000  # longer responses are truncated in the log (not the transcript)
    display_commands: list[str] | None = None  # what to show in logs instead of ``commands`` (e.g. unrendered lines)
    mask_values: list[str] = field(default_factory=list, repr=False)  # literal strings masked in logs/transcripts
    mask_pattern: str | None = None  # regex whose matches are masked in logs, transcript and raw log

    def __post_init__(self) -> None:
        if self.send_method not in SEND_METHODS:
            raise ValueError(f"send_method must be one of {SEND_METHODS}, got {self.send_method!r}")
        if self.error_pattern:
            re.compile(self.error_pattern)  # fail early on a bad regex
        if self.warning_pattern:
            re.compile(self.warning_pattern)
        if self.success_pattern:
            re.compile(self.success_pattern)
        if self.connect_retries < 0:
            raise ValueError("connect_retries must be >= 0")
        if self.pause_seconds < 0:
            raise ValueError("pause_seconds must be >= 0")
        if self.mask_pattern:
            re.compile(self.mask_pattern)
        if self.display_commands is not None and len(self.display_commands) != len(self.commands):
            raise ValueError("display_commands must have one entry per command")
        if not self.host or not self.username:
            raise ValueError("host and username are required")


@dataclass
class CommandResult:
    command: str
    response: str = ""
    ok: bool = True
    warning: bool = False
    error: str = ""
    elapsed: float = 0.0


@dataclass
class SessionResult:
    host: str
    label: str
    device_type: str
    connected: bool = False
    prompt: str = ""
    host_key: str = ""  # "<type> <sha256 fingerprint>" of the SSH host key that answered
    commands: list[CommandResult] = field(default_factory=list)
    error: str = ""  # connection-level / fatal error for this device
    dry_run: bool = False
    duration: float = 0.0
    transcript: str = ""  # human readable "sending/response" transcript
    raw_session_log: str = ""  # everything that crossed the SSH channel (secrets scrubbed)

    @property
    def sent(self) -> int:
        return len(self.commands)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.commands if not c.ok)

    @property
    def warned(self) -> int:
        return sum(1 for c in self.commands if c.ok and c.warning)

    @property
    def ok(self) -> bool:
        return self.connected and not self.error and self.failed == 0


# --------------------------------------------------------------------------- logging


class SessionLogger:
    """Minimal logging interface. Subclass (or duck-type) to redirect output.

    ``sending`` / ``response`` exist so a UI-aware subclass (the Nautobot job) can
    format them differently (e.g. Markdown code fences) without the runner knowing.
    """

    def debug(self, msg: str) -> None:  # pragma: no cover - trivial
        pass

    def info(self, msg: str) -> None:  # pragma: no cover - trivial
        pass

    def warning(self, msg: str) -> None:  # pragma: no cover - trivial
        pass

    def error(self, msg: str) -> None:  # pragma: no cover - trivial
        pass

    def sending(self, command: str) -> None:
        self.info(f"sending: {command}")

    def response(self, command: str, text: str, ok: bool = True, warn: bool = False) -> None:
        emit = self.error if not ok else (self.warning if warn else self.info)
        emit(f"response: {text}")


class PrintLogger(SessionLogger):
    """Prints to stdout; handy for shell experiments."""

    def __init__(self, prefix: str = "") -> None:
        self.prefix = prefix

    def _emit(self, level: str, msg: str) -> None:
        print(f"{self.prefix}[{level}] {msg}")

    def debug(self, msg: str) -> None:
        self._emit("debug", msg)

    def info(self, msg: str) -> None:
        self._emit("info", msg)

    def warning(self, msg: str) -> None:
        self._emit("warning", msg)

    def error(self, msg: str) -> None:
        self._emit("error", msg)


# --------------------------------------------------------------------------- helpers


def normalise_commands(text: str) -> tuple[list[str], list[str]]:
    """Turn the operator's text box into a list of commands plus human-readable normalisation notes.

    * one command per line, surrounding whitespace stripped
    * Windows / old-Mac line endings, tabs, a BOM and zero-width characters are tolerated
    * blank lines and lines starting with ``#``, ``!`` or ``//`` are ignored
    * "smart" quotes and en/em dashes pasted from Word/Outlook/wikis are normalised to ASCII
    * remaining non-ASCII characters are reported (CLIs such as the APC NMC are ASCII only)
    """
    replacements = {
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2013": "-",  # en dash
        "\u2014": "-",  # em dash
        "\u00a0": " ",  # no-break space
        "\t": " ",
    }
    removals = ("\ufeff", "\u200b", "\u200c", "\u200d")
    notes: list[str] = []
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    commands: list[str] = []
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw
        for char in removals:
            if char in line:
                line = line.replace(char, "")
                notes.append(f"line {number}: removed invisible character U+{ord(char):04X}")
        for char, replacement in replacements.items():
            if char in line:
                line = line.replace(char, replacement)
                what = "tab" if char == "\t" else f"U+{ord(char):04X}"
                notes.append(f"line {number}: replaced {what} with {replacement!r}")
        line = line.strip()
        if not line or line.startswith(COMMENT_PREFIXES):
            continue
        odd = [c for c in line if ord(c) > 126]
        if odd:
            notes.append(
                f"line {number}: contains non-ASCII character(s) {', '.join(f'U+{ord(c):04X}' for c in odd[:5])}"
            )
        commands.append(line)
    return commands, notes


def parse_commands(text: str) -> list[str]:
    """Commands only (see :func:`normalise_commands`)."""
    return normalise_commands(text)[0]


def available_device_types() -> list[str]:
    return sorted(NETMIKO_CLASS_MAPPER)


def resolve_device_type(requested: str = "", *candidates: str | None) -> str:
    """Pick the netmiko device_type: the explicit request wins, then the first known candidate.

    Raises ``ValueError`` if an explicit request names an unknown driver.
    """
    requested = (requested or "").strip()
    if requested:
        if requested not in NETMIKO_CLASS_MAPPER:
            close = [t for t in available_device_types() if requested.split("_")[0] in t][:8]
            hint = f" Similar: {', '.join(close)}." if close else ""
            raise ValueError(f"Unknown netmiko device_type {requested!r}.{hint}")
        return requested
    for candidate in candidates:
        if candidate and candidate in NETMIKO_CLASS_MAPPER:
            return candidate
    return GENERIC_DEVICE_TYPE


def legacy_ssh_support() -> dict[str, bool]:
    """Report which legacy SSH algorithms the installed paramiko still offers.

    Old APC NMC2 firmware only speaks ``ssh-rsa`` host keys and SHA-1 Diffie-Hellman.
    paramiko 5.0 removed all of these; 4.0 removed ``ssh-dss``.
    """
    transport = paramiko.transport.Transport
    return {
        "paramiko_version": paramiko.__version__,  # type: ignore[dict-item]
        "ssh-rsa": "ssh-rsa" in transport._key_info,
        "diffie-hellman-group14-sha1": "diffie-hellman-group14-sha1" in transport._kex_info,
        "diffie-hellman-group1-sha1": "diffie-hellman-group1-sha1" in transport._kex_info,
    }


def environment_summary() -> str:
    """One line describing the SSH stack, for the top of a job log."""
    support = legacy_ssh_support()
    yn = {True: "yes", False: "no"}
    text = (
        f"netmiko {netmiko.__version__}, paramiko {support['paramiko_version']}; "
        f"legacy SHA-1 algorithms available: ssh-rsa signatures={yn[support['ssh-rsa']]}, "
        f"dh-group14-sha1={yn[support['diffie-hellman-group14-sha1']]}, "
        f"dh-group1-sha1={yn[support['diffie-hellman-group1-sha1']]}"
    )
    if not support["ssh-rsa"]:
        text += (
            " - devices that only sign with ssh-rsa (e.g. APC NMC2 cards) cannot connect with this paramiko; "
            "install 'netmiko[par4]' (paramiko<5) if the fleet contains them"
        )
    return text


#: paramiko texts that mean the two sides could not agree on algorithms or the host key is wrong
_NEGOTIATION_TEXTS = (
    "incompatible ssh peer",
    "no acceptable",
    "can't match requested host key type",
    "host key for server",  # BadHostKeyException: "Host key for server 'x' does not match!"
)
#: paramiko texts for transient failures while connecting (worth a retry, no crypto hint)
_TRANSIENT_TEXTS = (
    "error reading ssh protocol banner",
    "key-exchange timed out",
    "connection dropped",
    "no existing session",
    "connection reset",
    "connection timed out",
    "eof",
)


def _looks_like_negotiation_failure(message: str) -> bool:
    """netmiko wraps paramiko's IncompatiblePeer / BadHostKeyException in NetmikoTimeoutException."""
    lowered = message.lower()
    return any(token in lowered for token in _NEGOTIATION_TEXTS)


def _legacy_hint() -> str:
    support = legacy_ssh_support()
    missing = [k for k, v in support.items() if k != "paramiko_version" and not v]
    if not missing:
        return ""
    return (
        f" Installed paramiko {support['paramiko_version']} no longer offers {', '.join(missing)}; "
        "legacy NMC2 firmware needs those. Either upgrade the device firmware or install "
        "'paramiko<5' in the Nautobot environment."
    )


def _scrub(text: str, *secrets: str) -> str:
    """Mask credentials in text netmiko captured from the channel.

    netmiko already filters the login password/secret out of its session log; this is
    belt-and-braces. Very short secrets are skipped because masking them would also
    mangle unrelated text (a password of "apc" would hit "apc_aos").
    """
    for secret in secrets:
        if secret and len(secret) >= 6:
            text = text.replace(secret, "********")
    return text


def _channel_alive(conn) -> bool:
    """True while the SSH channel and transport are still open (a device can close them after a command)."""
    channel = getattr(conn, "remote_conn", None)
    if channel is None or getattr(channel, "closed", False):
        return False
    transport = getattr(channel, "transport", None)
    return bool(transport is not None and transport.is_active())


def _salvage_output(raw_log: io.BytesIO, start: int, command: str, conn) -> str:
    """Whatever the device sent after ``start`` (session-log offset) plus anything still buffered."""
    text = raw_log.getvalue()[start:].decode("utf-8", errors="replace")
    try:
        text += conn.read_channel()
    except Exception:
        pass
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line for line in text.split("\n") if line.strip() and line.strip() != command.strip()]
    # drop the echoed command when it is glued to the prompt ("apc>dns -p ...")
    lines = [line for line in lines if not line.rstrip().endswith(command.strip())]
    return "\n".join(lines).strip()


def _condense(exc: BaseException, limit: int = 240) -> str:
    """Collapse a (possibly multi-line) exception message into one short line."""
    text = " ".join(str(exc).split()) or exc.__class__.__name__
    return text if len(text) <= limit else text[: limit - 3] + "..."


class _Masker:
    """Masks operator-declared secrets (literal values and/or a regex) in anything we log or attach."""

    def __init__(self, values: list[str], pattern: str | None) -> None:
        # operator-declared secrets are masked whatever their length (the length guard in _scrub only
        # protects against the *login* password mangling unrelated text)
        self.values = sorted({v for v in values if v}, key=len, reverse=True)
        self.regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE) if pattern else None

    def __call__(self, text: str) -> str:
        for value in self.values:
            text = text.replace(value, "****")
        if self.regex is not None:
            text = self.regex.sub("****", text)
        return text


def _truncate(text: str, limit: int) -> str:
    if limit and len(text) > limit:
        return text[:limit] + f"\n... [truncated {len(text) - limit} chars; see transcript file]"
    return text


# --------------------------------------------------------------------------- connecting


def _classify_connect_error(spec: SessionSpec, exc: BaseException) -> tuple[str, bool]:
    """Return (message, retryable) for an exception raised by ConnectHandler()."""
    if isinstance(exc, NetmikoAuthenticationException):
        # netmiko appends a long "common causes" essay; keep the first sentence only
        return f"authentication failed for user {spec.username!r}: {_condense(exc).split(' Common causes')[0]}", False
    if isinstance(exc, NetmikoTimeoutException):
        # netmiko raises this for TCP/DNS failures AND for any paramiko SSHException during connect:
        # IncompatiblePeer ("no acceptable host key" / "no acceptable kex algorithm"), BadHostKeyException,
        # but also transient ones such as "Error reading SSH protocol banner" (peer closed/reset early)
        message = _condense(exc)
        inner = message.split("connection creation: ", 1)[-1] if "SSHException occurred" in message else message
        if _looks_like_negotiation_failure(inner):
            hint = _legacy_hint() if "host key for server" not in inner.lower() else ""
            return f"SSH negotiation failed: {inner}.{hint}", False
        if "SSHException occurred" in message:
            return f"SSH connection failed: {inner}", True
        return f"connection failed ({spec.conn_timeout}s timeout): {message.split(' Common causes')[0]}", True
    if isinstance(exc, (ReadTimeout, ReadException)):
        # the driver logged in but never saw a prompt: forced password change on first login, a
        # banner the driver does not expect, or a device that is not what the device_type assumes
        # (wording keeps punctuation right after "password" so Nautobot's log sanitizer leaves it alone)
        detail = _condense(exc).split(" Things you might try")[0]
        return (
            "logged in but no CLI prompt appeared (first login requiring a new password? wrong device_type? "
            f"a lingering session on the device?): {detail[:160]}",
            True,
        )
    if isinstance(exc, paramiko.ssh_exception.IncompatiblePeer):
        return f"SSH algorithm negotiation failed: {_condense(exc)}.{_legacy_hint()}", False
    if isinstance(exc, SSHException):
        msg = _condense(exc)
        if _looks_like_negotiation_failure(msg):
            return f"SSH negotiation failed: {msg}.{_legacy_hint()}", False
        return f"SSH error: {msg}", any(t in msg.lower() for t in _TRANSIENT_TEXTS)
    if isinstance(exc, (OSError, EOFError)):
        return f"network error: {_condense(exc)}", True
    if isinstance(exc, ValueError):  # netmiko raises ValueError when it cannot find a prompt
        return f"logged in but could not find a CLI prompt: {_condense(exc)}", True
    raise exc


def _host_key_info(conn) -> str:
    """'<type> SHA256:<fingerprint>' of the server host key, or '' if unavailable."""
    try:
        key = conn.remote_conn.transport.get_remote_server_key()
        digest = hashlib.sha256(key.asbytes()).digest()
        return f"{key.get_name()} SHA256:{base64.b64encode(digest).decode().rstrip('=')}"
    except Exception:
        return ""


def _connect(spec: SessionSpec, log: SessionLogger, label: str, raw_log: io.BytesIO | None):
    """Open the netmiko connection with retries. Returns (conn, error_message)."""
    device_type = resolve_device_type(spec.device_type)
    connect_kwargs = dict(
        device_type=device_type,
        host=spec.host,
        port=spec.port,
        username=spec.username,
        password=spec.password,
        secret=spec.secret or "",
        conn_timeout=spec.conn_timeout,
        banner_timeout=max(30.0, 2 * spec.conn_timeout),  # loaded management cards are slow to banner
        auth_timeout=max(30.0, 2 * spec.conn_timeout),
        global_delay_factor=spec.global_delay_factor,
        session_log_record_writes=True,
        keepalive=spec.keepalive,
    )
    if raw_log is not None:
        connect_kwargs["session_log"] = raw_log
    if spec.disabled_algorithms:
        connect_kwargs["disabled_algorithms"] = spec.disabled_algorithms
    if spec.ssh_config_file:
        connect_kwargs["ssh_config_file"] = spec.ssh_config_file
    if spec.known_hosts_file:
        # reject unknown or changed host keys instead of netmiko's default accept-anything policy
        connect_kwargs.update(ssh_strict=True, alt_host_keys=True, alt_key_file=spec.known_hosts_file)

    attempts = 1 + max(0, spec.connect_retries)
    backoff = spec.retry_backoff
    error = ""
    for attempt in range(1, attempts + 1):
        try:
            return ConnectHandler(**connect_kwargs), ""
        except Exception as exc:
            error, retryable = _classify_connect_error(spec, exc)
            if not retryable or attempt == attempts:
                return None, error
            log.warning(f"{label}: attempt {attempt}/{attempts} failed ({error}); retrying in {backoff:g}s")
            time.sleep(backoff)
            backoff *= 2
    return None, error  # pragma: no cover - loop always returns


def verify_login(spec: SessionSpec, log: SessionLogger | None = None) -> tuple[bool, str]:
    """Log in once more (no commands) to prove the credentials still work, e.g. after RADIUS/user changes."""
    log = log or SessionLogger()
    label = spec.label or spec.host
    conn, error = _connect(spec, log, label, None)
    if conn is None:
        return False, error
    try:
        try:
            prompt = conn.find_prompt()
        except (ValueError, ReadTimeout, NetmikoTimeoutException) as exc:
            return False, f"re-login succeeded but no prompt appeared: {_condense(exc, 160)}"
        log.info(f"{label}: re-login OK (prompt {prompt!r})")
        if spec.logout_command:
            try:
                conn.write_channel(spec.logout_command + conn.RETURN)
                time.sleep(0.5)
            except Exception:
                pass
        return True, ""
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


# --------------------------------------------------------------------------- runner


def run_session(spec: SessionSpec, log: SessionLogger | None = None) -> SessionResult:
    """Open one SSH session, run every command in order, return a :class:`SessionResult`.

    Never raises for device-side problems; they are reported in the result and the log.
    Programming errors (bad regex, unknown device_type) still raise.
    """
    log = log or SessionLogger()
    label = spec.label or spec.host
    device_type = resolve_device_type(spec.device_type)
    result = SessionResult(host=spec.host, label=label, device_type=device_type, dry_run=spec.dry_run)
    transcript: list[str] = [
        f"=== {label} ({spec.host}:{spec.port}) device_type={device_type} user={spec.username} ===",
    ]
    error_re = re.compile(spec.error_pattern, re.IGNORECASE | re.MULTILINE) if spec.error_pattern else None
    success_re = re.compile(spec.success_pattern, re.IGNORECASE | re.MULTILINE) if spec.success_pattern else None
    warn_re = re.compile(spec.warning_pattern, re.IGNORECASE | re.MULTILINE) if spec.warning_pattern else None
    mask = _Masker(spec.mask_values, spec.mask_pattern)
    shown_commands = spec.display_commands if spec.display_commands is not None else spec.commands
    dropped_as_expected = False
    raw_log = io.BytesIO()
    started = time.monotonic()

    def finish() -> SessionResult:
        result.duration = round(time.monotonic() - started, 2)
        transcript.append(
            f"=== done: connected={result.connected} sent={result.sent} failed={result.failed} warned={result.warned} "
            f"error={result.error or 'none'} duration={result.duration}s ==="
        )
        # the transcript is built from our own strings and never contains the login credentials;
        # operator-declared secrets (mask_values / mask_pattern) are masked in both outputs
        result.transcript = mask("\n".join(transcript))
        result.raw_session_log = mask(
            _scrub(raw_log.getvalue().decode("utf-8", errors="replace"), spec.password, spec.secret)
        )
        return result

    # ---- connect
    log.info(f"connecting to {label} at {spec.host}:{spec.port} as {spec.username} (device_type={device_type})")
    conn, result.error = _connect(spec, log, label, raw_log)
    if conn is None:
        log.error(f"{label}: {result.error}")
        transcript.append(f"CONNECT FAILED: {result.error}")
        return finish()

    result.connected = True
    try:
        # ---- prompt detection
        send_method = spec.send_method
        try:
            prompt = conn.find_prompt()
        except (ValueError, ReadTimeout, NetmikoTimeoutException) as exc:
            prompt = ""
            log.warning(f"{label}: could not detect a prompt ({exc}); using timing-based sends")
            send_method = "timing"
        if prompt and not conn.base_prompt:
            # generic drivers never set base_prompt; netmiko needs it to strip the trailing prompt
            conn.base_prompt = prompt[:-1] if len(prompt) > 1 else prompt
        result.prompt = prompt
        result.host_key = _host_key_info(conn)
        log.info(f"connected to {label}; prompt detected: {prompt!r}" if prompt else f"connected to {label}")
        if result.host_key:
            log.debug(f"{label}: host key {result.host_key}")
        transcript.append(f"connected; prompt={prompt!r}; host key={result.host_key or 'unknown'}")

        if spec.enter_enable:
            try:
                conn.enable()
                log.info(f"{label}: entered enable mode")
            except Exception as exc:
                result.error = f"could not enter enable mode: {exc}"
                log.error(f"{label}: {result.error}")
                return finish()

        # ---- commands
        total = len(spec.commands)
        if spec.dry_run:
            for shown in shown_commands:
                log.info(f"dry run - would send: {mask(shown)}")
                transcript.append(f"dry run - would send: {shown}")
            log.info(f"{label}: dry run complete, nothing was sent")
            return finish()

        for index, (cmd, shown_cmd) in enumerate(zip(spec.commands, shown_commands), start=1):
            log.sending(mask(shown_cmd))
            transcript.append(f"sending: {shown_cmd}")
            t0 = time.monotonic()
            cr = CommandResult(command=cmd)
            raw_pos = len(raw_log.getvalue())
            try:
                if send_method == "prompt":
                    out = conn.send_command(
                        cmd,
                        read_timeout=spec.command_timeout,
                        strip_prompt=True,
                        strip_command=True,
                    )
                else:
                    out = conn.send_command_timing(
                        cmd,
                        read_timeout=spec.command_timeout,
                        last_read=max(2.0, spec.global_delay_factor),  # NMC2 cards are slow between chunks
                        strip_prompt=True,
                        strip_command=True,
                    )
                cr.response = str(out).strip()
            except ReadTimeout as exc:
                # netmiko discards what the device sent when it gives up; recover it from the session log
                cr.response = _salvage_output(raw_log, raw_pos, cmd, conn)
                if not _channel_alive(conn):
                    # the device closed the session (reboot, exit, hostname change) and netmiko only noticed
                    # as a missing prompt
                    if spec.disconnect_ok_on_last_command and index == total:
                        dropped_as_expected = True
                        cr.response = cr.response or "<connection closed by device>"
                        log.info(f"{label}: connection closed by the device after the last command (expected)")
                    else:
                        cr.ok = False
                        cr.error = "connection closed by the device after this command"
                        result.error = cr.error
                else:
                    cr.ok = False
                    cr.error = (
                        f"no prompt within {spec.command_timeout}s; device output so far is shown as the response "
                        f"({_condense(exc).split(' Things you might try')[0][:120]})"
                    )
            except (OSError, EOFError, SSHException) as exc:
                if spec.disconnect_ok_on_last_command and index == total:
                    dropped_as_expected = True
                    cr.response = cr.response or "<connection closed by device>"
                    log.info(f"{label}: connection closed by the device after the last command (expected)")
                else:
                    cr.ok = False
                    cr.error = f"connection lost while running command: {_condense(exc)}"
                    result.error = cr.error
            cr.elapsed = round(time.monotonic() - t0, 2)

            if cr.ok and not dropped_as_expected and not _channel_alive(conn):
                # the device closed the session after this command (reboot, 'exit', hostname change...)
                if spec.disconnect_ok_on_last_command and index == total:
                    dropped_as_expected = True
                    log.info(f"{label}: connection closed by the device after the last command (expected)")
                else:
                    cr.ok = False
                    cr.error = "connection closed by the device after this command"
                    result.error = cr.error

            if cr.ok and error_re and error_re.search(cr.response):
                cr.ok = False
                cr.error = f"response matched error pattern {spec.error_pattern!r}"
            elif cr.ok and success_re and not dropped_as_expected and not success_re.search(cr.response):
                cr.ok = False
                cr.error = f"response did not match success pattern {spec.success_pattern!r}"
            elif cr.ok and warn_re and warn_re.search(cr.response):
                cr.warning = True

            shown = cr.response or NO_OUTPUT
            log.response(shown_cmd, _truncate(mask(shown), spec.max_log_chars), ok=cr.ok, warn=cr.warning)
            transcript.append(f"response: {shown}")
            if cr.error:
                log.error(f"{label}: command {index}/{total} failed: {cr.error}")
                transcript.append(f"ERROR: {cr.error}")
            elif cr.warning:
                log.warning(f"{label}: command {index}/{total} matched warning pattern {spec.warning_pattern!r}")
                transcript.append("WARNING: matched warning pattern")
            result.commands.append(cr)

            if result.error:  # connection is gone; nothing more to do
                break
            if not cr.ok and spec.stop_on_error:
                remaining = total - index
                if remaining:
                    log.warning(f"{label}: 'Stop device on error' is set; skipping remaining {remaining} command(s)")
                    transcript.append(f"stopped; {remaining} command(s) not sent")
                break
            if spec.pause_seconds and index < total:
                time.sleep(spec.pause_seconds)
    finally:
        if spec.logout_command and not result.error and not dropped_as_expected:
            try:
                conn.write_channel(spec.logout_command + conn.RETURN)
                time.sleep(0.5)
            except Exception:
                pass
        try:
            conn.disconnect()
        except Exception:
            pass
    return finish()


def run_many(specs: Sequence[SessionSpec], log: SessionLogger | None = None) -> list[SessionResult]:
    """Run sessions sequentially; convenience for scripts."""
    return [run_session(spec, log) for spec in specs]
