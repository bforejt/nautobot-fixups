"""Opt-in end-to-end test: run the real SSHFixupEngine Job inside Nautobot against the fake APC server.

Skipped unless NAUTOBOT_E2E=1 and DJANGO_SETTINGS_MODULE points at a migrated database
(see tests/e2e/run_e2e.sh, which sets everything up in Docker).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("NAUTOBOT_E2E"), reason="set NAUTOBOT_E2E=1 (see tests/e2e)")

REPO_ROOT = Path(__file__).resolve().parent.parent
APC_ERROR_PATTERN = r"^E1\d{2}:"


@pytest.fixture(scope="module")
def nb():
    """Configure Django/Nautobot once, register the job, and build a tiny inventory + secrets group."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "nautobot_config_e2e")
    os.environ["E2E_APC_USER"] = "apc"
    os.environ["E2E_APC_PASS"] = "apc"
    os.environ["E2E_RADIUS_SECRET"] = "Sup3rS3cretRadius"
    sys.path.insert(0, str(REPO_ROOT / "tests" / "e2e"))
    sys.path.insert(0, str(REPO_ROOT))
    import django

    django.setup()
    from django.contrib.contenttypes.models import ContentType
    from nautobot.dcim.models import Device, DeviceType, Interface, Location, LocationType, Manufacturer, Platform
    from nautobot.extras.choices import SecretsGroupAccessTypeChoices as AT
    from nautobot.extras.choices import SecretsGroupSecretTypeChoices as ST
    from nautobot.extras.models import (
        DynamicGroup,
        FileProxy,
        JobLogEntry,
        Role,
        Secret,
        SecretsGroup,
        SecretsGroupAssociation,
        Status,
        Tag,
    )
    from nautobot.extras.models import Job as JobModel
    from nautobot.ipam.models import IPAddress, Namespace, Prefix

    import jobs  # noqa: F401 - registers SSHFixupEngine

    ct_device = ContentType.objects.get_for_model(Device)
    active = Status.objects.get(name="Active")
    for model in (Device, Location, IPAddress, Prefix, Interface):
        active.content_types.add(ContentType.objects.get_for_model(model))
    lt, _ = LocationType.objects.get_or_create(name="E2E Site")
    lt.content_types.add(ct_device)
    loc, _ = Location.objects.get_or_create(name="E2E Lab", location_type=lt, defaults={"status": active})
    mfr, _ = Manufacturer.objects.get_or_create(name="APC by Schneider Electric")
    dt, _ = DeviceType.objects.get_or_create(manufacturer=mfr, model="AP9641")
    role, _ = Role.objects.get_or_create(name="e2e-pdu")
    role.content_types.add(ct_device)
    platform, _ = Platform.objects.get_or_create(name="APC AOS", defaults={"manufacturer": mfr})
    tag, _ = Tag.objects.get_or_create(name="e2e-apc-fixup")
    tag.content_types.add(ct_device)
    pending, _ = Tag.objects.get_or_create(name="e2e-fixup-pending")
    pending.content_types.add(ct_device)
    done, _ = Tag.objects.get_or_create(name="e2e-fixup-done")
    done.content_types.add(ct_device)
    ns = Namespace.objects.get(name="Global")
    Prefix.objects.get_or_create(prefix="127.0.0.0/8", namespace=ns, defaults={"status": active})

    planned, _ = Status.objects.get_or_create(name="Planned")
    planned.content_types.add(ct_device)

    def device(name, host=None, tagged=False, status=None):
        dev, _ = Device.objects.get_or_create(
            name=name,
            defaults={
                "device_type": dt,
                "role": role,
                "location": loc,
                "status": status or active,
                "platform": platform,
            },
        )
        if host:
            ip, _ = IPAddress.objects.get_or_create(address=f"{host}/32", namespace=ns, defaults={"status": active})
            iface, _ = Interface.objects.get_or_create(
                device=dev, name="mgmt", defaults={"type": "virtual", "status": active}
            )
            iface.ip_addresses.add(ip)
            dev.primary_ip4 = ip
            dev.validated_save()
        if tagged:
            dev.tags.add(tag)
        return dev

    def secret(name, var):
        return Secret.objects.get_or_create(
            name=name, defaults={"provider": "environment-variable", "parameters": {"variable": var}}
        )[0]

    sg, _ = SecretsGroup.objects.get_or_create(name="e2e-apc-creds")
    SecretsGroupAssociation.objects.get_or_create(
        secrets_group=sg,
        secret=secret("e2e-apc-username", "E2E_APC_USER"),
        access_type=AT.TYPE_GENERIC,
        secret_type=ST.TYPE_USERNAME,
    )
    SecretsGroupAssociation.objects.get_or_create(
        secrets_group=sg,
        secret=secret("e2e-apc-password", "E2E_APC_PASS"),
        access_type=AT.TYPE_GENERIC,
        secret_type=ST.TYPE_PASSWORD,
    )
    job_model = JobModel.objects.get(job_class_name="SSHFixupEngine")
    job_model.enabled = True
    job_model.validated_save()

    class NB:
        pass

    env = NB()
    env.job_model = job_model
    env.sg = sg
    env.tag = tag
    env.pending = pending
    env.done = done
    env.loc = loc
    env.d1 = device("e2e-apc-1", "127.0.0.1", tagged=True)
    env.d2 = device("e2e-apc-2")  # no primary IP -> skipped in pre-flight
    env.d3 = device("e2e-apc-3", "127.0.0.1")  # same loopback IP: macOS has no 127.0.0.2 alias by default
    env.d_planned = device("e2e-apc-planned", "127.0.0.1", status=planned)
    secret("e2e-radius-secret", "E2E_RADIUS_SECRET")
    env.dynamic_group, _ = DynamicGroup.objects.get_or_create(
        name="e2e-apc-group", defaults={"content_type": ct_device, "filter": {"tags": [tag.name]}}
    )
    env.dynamic_group.update_cached_members()
    env.JobLogEntry = JobLogEntry
    env.FileProxy = FileProxy
    return env


@pytest.fixture
def apc():
    sys.path.insert(0, str(REPO_ROOT / "tests"))
    from fake_apc_server import FakeApcServer

    with FakeApcServer(name="e2e-apc-1") as server:
        yield server


COMMANDS = (
    "tcpip -d example.local\n"
    "Email -f1 {{ device.name }}@example.local\n"
    "# a comment line\n"
    "dns -p 10.0.0.3 -s 10.0.0.4 -d example.local\n"
    "Email -t1 bogus\n"
    "ntp -p 10.0.0.5 -s 10.0.0.6\n"
)


def run(nb, apc, **overrides):
    from nautobot.core.testing import run_job_for_testing

    kwargs = dict(
        devices=[nb.d1.pk],
        tags=[],
        dynamic_groups=[],
        include_non_active=False,
        max_devices=50,
        canary_count=1,
        max_device_failures=3,
        change_reference="CHG-0001",
        remove_tag_on_success=None,
        add_tag_on_success=None,
        secrets_group=nb.sg.pk,
        commands=COMMANDS,
        render_jinja=True,
        deny_pattern="",
        mask_pattern="",
        pause_seconds=0,
        command_timeout=10,
        conn_timeout=3,
        connect_retries=0,
        legacy_ssh_algorithms=False,
        known_hosts_file="",
        ssh_port=apc.port,
        netmiko_device_type="",
        send_method="prompt",
        prompt_pattern="",
        error_pattern="",
        success_pattern="",
        warning_pattern="",
        stop_on_error=True,
        disconnect_ok_on_last_command=False,
        verify_relogin=True,
        enter_enable_mode=False,
        logout_command="exit",
        attach_files=True,
        dryrun=False,
    )
    kwargs.update(overrides)
    job_result = run_job_for_testing(nb.job_model, **kwargs)
    logs = list(nb.JobLogEntry.objects.filter(job_result=job_result).order_by("created"))
    files = {}
    for fp in nb.FileProxy.objects.filter(job_result=job_result):
        fp.file.open("rb")
        files[fp.name] = fp.file.read().decode()
        fp.file.close()
    return job_result, logs, files


def outcome(job_result, files):
    """The structured outcome: JobResult.result, which must equal the attached results file."""
    result = job_result.result
    assert isinstance(result, dict), result
    if "ssh-fixup-results.json" in files:
        assert json.loads(files["ssh-fixup-results.json"]) == result
    return result


def assert_failed(job_result):
    assert job_result.status == "FAILURE", (job_result.status, job_result.result)


def messages(logs, level=None, grouping=None):
    return [
        e.message
        for e in logs
        if (level is None or e.log_level == level) and (grouping is None or e.grouping == grouping)
    ]


def test_dry_run_via_tag_filter(nb, apc):
    job_result, logs, files = run(nb, apc, devices=[], tags=[nb.tag.pk], dryrun=True)
    assert job_result.status == "SUCCESS", job_result.result
    msgs = messages(logs, grouping="e2e-apc-1")
    assert any("prompt detected: 'apc>'" in m for m in msgs)
    assert any("dry run - would send: tcpip -d example.local" in m for m in msgs)
    assert not any(m.startswith("sending:") for m in msgs)
    assert [c for c in apc.received if c != "exit"] == []
    setup = messages(logs, grouping="setup")
    assert any(m.startswith("plan:\n\n| # |") and "| e2e-apc-1 |" in m for m in setup)
    assert "ssh-fixup-transcript.txt" in files and "ssh-fixup-results.json" in files
    out = outcome(job_result, files)
    assert out["mode"] == "dry-run" and out["devices"]["e2e-apc-1"]["status"] == "dry-run"
    assert job_result.result["mode"] == "dry-run"  # SUCCESS runs keep the return value as the JobResult result


def test_live_run_logs_sending_and_response_pairs(nb, apc):
    job_result, logs, files = run(nb, apc)
    assert job_result.status == "SUCCESS", job_result.result
    msgs = messages(logs, grouping="e2e-apc-1")
    assert any("netmiko device_type apc_aos (APC/Schneider" in m for m in msgs)  # manufacturer heuristic
    assert "sending: `tcpip -d example.local`" in msgs
    assert "response: `E000: Success`" in msgs
    assert "response: `E102: Parameter Error`" in msgs  # no error pattern -> info, job still succeeds
    assert any("re-login OK" in m for m in msgs)  # verify_relogin
    # Nautobot's global log sanitizer redacts anything that looks like user@host, e-mail addresses included
    assert "sending: `Email -f1 (redacted)@example.local`" in msgs
    # ... but the transcript attachment is verbatim
    transcript = files["ssh-fixup-transcript.txt"]
    assert "change CHG-0001" in transcript
    assert "sending: Email -f1 e2e-apc-1@example.local\nresponse: E000: Success" in transcript
    assert "raw SSH session log" in transcript and "Network Management Card AOS" in transcript
    assert apc.received == [
        "tcpip -d example.local",
        "Email -f1 e2e-apc-1@example.local",
        "dns -p 10.0.0.3 -s 10.0.0.4 -d example.local",
        "Email -t1 bogus",
        "ntp -p 10.0.0.5 -s 10.0.0.6",
        "exit",
        "exit",  # the re-login check logs out too
    ]
    summary = messages(logs, grouping="summary")
    assert any("| e2e-apc-1 | 127.0.0.1 | OK | 5 | 0 | 0 |" in m for m in summary)
    results = outcome(job_result, files)
    assert results["ok"] == 1 and results["failed"] == 0 and results["change_reference"] == "CHG-0001"
    assert results["devices"]["e2e-apc-1"]["host_key"].startswith("ssh-rsa SHA256:")
    assert "ssh-fixup-results.json" in files


def test_error_pattern_fails_device_and_job(nb, apc):
    job_result, logs, files = run(nb, apc, error_pattern=APC_ERROR_PATTERN, canary_count=0)
    assert_failed(job_result)
    out = outcome(job_result, files)
    assert out["failed"] == 1 and out["ok"] == 0
    d1 = messages(logs, grouping="e2e-apc-1")
    assert any("command 4/5 failed: response matched error pattern" in m for m in d1)
    assert any("skipping remaining 1 command" in m for m in messages(logs, "warning", "e2e-apc-1"))
    assert "ntp -p 10.0.0.5 -s 10.0.0.6" not in apc.received
    assert any("1 failed" in m for m in messages(logs, grouping="summary"))


def test_device_without_primary_ip_is_skipped_not_attempted(nb, apc):
    job_result, logs, files = run(nb, apc, devices=[nb.d1.pk, nb.d2.pk])
    assert job_result.status == "SUCCESS", job_result.result  # skipped devices do not fail the run
    out = outcome(job_result, files)
    assert out["skipped"] == 1 and out["ok"] == 1
    assert out["devices"]["e2e-apc-2"]["status"] == "skipped"
    assert any("no primary IP address" in m for m in messages(logs, grouping="e2e-apc-2"))


def test_unknown_device_type_fails_fast(nb, apc):
    job_result, _, _ = run(nb, apc, netmiko_device_type="apc_nope")
    assert job_result.status == "FAILURE"
    assert "Unknown netmiko device_type 'apc_nope'" in job_result.result["exc_message"]
    assert apc.received == []


def test_no_commands_fails_fast(nb, apc):
    job_result, _, _ = run(nb, apc, commands="# only a comment\n\n")
    assert job_result.status == "FAILURE"
    assert "No commands given" in job_result.result["exc_message"]


def test_max_devices_guard(nb, apc):
    job_result, _, _ = run(nb, apc, devices=[nb.d1.pk, nb.d2.pk], max_devices=1)
    assert job_result.status == "FAILURE"
    assert "Maximum devices" in job_result.result["exc_message"]
    assert apc.received == []


def test_template_error_is_caught_in_preflight(nb, apc):
    job_result, _, _ = run(nb, apc, commands="dns -p {{ device.nam }}\n")
    assert job_result.status == "FAILURE"
    assert "Pre-flight failed" in job_result.result["exc_message"]
    assert "undefined name" in job_result.result["exc_message"]
    assert apc.received == []


def test_deny_pattern_refuses_run(nb, apc):
    job_result, _, _ = run(nb, apc, commands="about\nreboot\n", deny_pattern=r"^reboot\b")
    assert job_result.status == "FAILURE"
    assert "matches the deny pattern" in job_result.result["exc_message"]
    assert apc.received == []


def test_canary_abort_before_second_device(nb, apc):
    # e2e-apc-1 is the canary (name order); make it fail via the error pattern -> e2e-apc-3 is never attempted
    job_result, logs, files = run(
        nb, apc, devices=[nb.d1.pk, nb.d3.pk], error_pattern=APC_ERROR_PATTERN, canary_count=1, max_device_failures=0
    )
    assert_failed(job_result)
    out = outcome(job_result, files)
    assert out["failed"] == 1 and out["not_attempted"] == 1
    assert "canary device" in out["aborted"]
    assert not messages(logs, grouping="e2e-apc-3")


def test_dynamic_group_selection(nb, apc):
    job_result, _, files = run(nb, apc, devices=[], dynamic_groups=[nb.dynamic_group.pk], dryrun=True)
    assert job_result.status == "SUCCESS", job_result.result
    assert set(outcome(job_result, files)["devices"]) == {"e2e-apc-1"}


def test_secret_helper_keeps_secret_out_of_log(nb, apc):
    job_result, logs, files = run(nb, apc, commands='radius -s1 {{ secret("e2e-radius-secret") }}\n')
    assert job_result.status == "SUCCESS", job_result.result
    assert apc.received[0] == "radius -s1 Sup3rS3cretRadius"  # the device got the real value
    blob = "\n".join(e.message for e in logs) + files["ssh-fixup-transcript.txt"] + files["ssh-fixup-results.json"]
    assert "Sup3rS3cretRadius" not in blob
    assert any(
        m == 'sending: `radius -s1 {{ secret("e2e-radius-secret") }}`' for m in messages(logs, grouping="e2e-apc-1")
    )


def test_non_active_device_is_skipped_unless_included(nb, apc):
    job_result, _, files = run(nb, apc, devices=[nb.d1.pk, nb.d_planned.pk], dryrun=True)
    assert job_result.status == "SUCCESS", job_result.result
    out = outcome(job_result, files)
    assert (
        out["devices"]["e2e-apc-planned"]["status"] == "skipped" and out["devices"]["e2e-apc-1"]["status"] == "dry-run"
    )
    job_result, _, files = run(nb, apc, devices=[nb.d1.pk, nb.d_planned.pk], dryrun=True, include_non_active=True)
    assert outcome(job_result, files)["devices"]["e2e-apc-planned"]["status"] == "dry-run"


def test_sandboxed_templates_cannot_reach_the_orm(nb, apc):
    job_result, _, _ = run(nb, apc, commands="about {{ device._meta.apps }}\n")
    assert_failed(job_result)
    assert "Pre-flight failed" in job_result.result["exc_message"]
    job_result, _, _ = run(nb, apc, commands="about {{ device.save() }}\n")
    assert_failed(job_result)
    assert apc.received == []


def test_rendered_control_characters_are_refused(nb, apc):
    job_result, _, _ = run(nb, apc, commands='about {{ "x\\rreboot" }}\n')
    assert_failed(job_result)
    assert "control characters" in job_result.result["exc_message"]
    assert apc.received == []


def test_negative_integers_are_refused(nb, apc):
    job_result, _, _ = run(nb, apc, canary_count=-1)
    assert_failed(job_result)
    assert "must be 0 or more" in job_result.result["exc_message"]


def test_all_devices_skipped_is_a_failure(nb, apc):
    job_result, _, _ = run(nb, apc, devices=[nb.d2.pk], dryrun=True)  # no primary IP -> skipped
    assert_failed(job_result)
    assert "would be skipped" in job_result.result["exc_message"]


def test_success_tags_are_flipped_only_for_ok_live_devices(nb, apc):
    nb.d1.tags.add(nb.pending)
    nb.d1.tags.remove(nb.done)
    # dry run: nothing changes, log says what would happen
    job_result, logs, files = run(
        nb, apc, remove_tag_on_success=nb.pending.pk, add_tag_on_success=nb.done.pk, dryrun=True
    )
    assert job_result.status == "SUCCESS", job_result.result
    assert nb.d1.tags.filter(pk=nb.pending.pk).exists() and not nb.d1.tags.filter(pk=nb.done.pk).exists()
    assert any("would remove tag 'e2e-fixup-pending'" in m for m in messages(logs, grouping="e2e-apc-1"))
    # failed device: tags untouched
    job_result, _, _ = run(
        nb, apc, remove_tag_on_success=nb.pending.pk, add_tag_on_success=nb.done.pk, error_pattern=APC_ERROR_PATTERN
    )
    assert_failed(job_result)
    assert nb.d1.tags.filter(pk=nb.pending.pk).exists() and not nb.d1.tags.filter(pk=nb.done.pk).exists()
    # live OK: pending removed, done added, recorded in log, summary and results
    job_result, logs, files = run(nb, apc, remove_tag_on_success=nb.pending.pk, add_tag_on_success=nb.done.pk)
    assert job_result.status == "SUCCESS", job_result.result
    assert not nb.d1.tags.filter(pk=nb.pending.pk).exists() and nb.d1.tags.filter(pk=nb.done.pk).exists()
    assert "removed tag 'e2e-fixup-pending'; added tag 'e2e-fixup-done'" in messages(logs, grouping="e2e-apc-1")
    out = outcome(job_result, files)
    assert out["devices"]["e2e-apc-1"]["tags"] == "removed tag 'e2e-fixup-pending'; added tag 'e2e-fixup-done'"
    assert "tags: removed from 1, added to 1" in out["summary"]
    # selecting by the pending tag now finds nothing left to do
    job_result, _, _ = run(nb, apc, devices=[], tags=[nb.pending.pk])
    assert_failed(job_result)
    assert "No devices selected" in job_result.result["exc_message"]
    nb.d1.tags.remove(nb.done)


def test_success_tags_must_differ(nb, apc):
    job_result, _, _ = run(nb, apc, remove_tag_on_success=nb.pending.pk, add_tag_on_success=nb.pending.pk)
    assert_failed(job_result)
    assert "must be different tags" in job_result.result["exc_message"]
