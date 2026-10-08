"""End-to-end tests for jobs/ssh_runner.py against the fake APC SSH server."""

from __future__ import annotations

import os

import pytest

APC_ERROR_PATTERN = r"^E1\d{2}:"


class Capture:
    """SessionLogger that records everything, for assertions."""

    def __init__(self, runner):
        self.lines: list[tuple[str, str]] = []
        base = runner.SessionLogger

        class _Logger(base):
            def debug(inner, msg):
                self.lines.append(("debug", msg))

            def info(inner, msg):
                self.lines.append(("info", msg))

            def warning(inner, msg):
                self.lines.append(("warning", msg))

            def error(inner, msg):
                self.lines.append(("error", msg))

        self.logger = _Logger()

    def messages(self, level=None):
        return [m for lvl, m in self.lines if level in (None, lvl)]


def base_spec(runner, apc, **overrides):
    params = dict(
        host=apc.host,
        port=apc.port,
        username=apc.username,
        password=apc.password,
        label="apc-lab-1",
        commands=["about"],
        pause_seconds=0.1,
        conn_timeout=10,
        command_timeout=10,
        connect_retries=0,
    )
    params.update(overrides)
    return runner.SessionSpec(**params)


# --------------------------------------------------------------------------- parsing


def test_parse_commands_strips_comments_blank_lines_and_smart_quotes(runner):
    nbsp, lquote, rquote = chr(0xA0), chr(0x201C), chr(0x201D)
    text = (
        "tcpip -d example.local\r\n"
        "# a comment\n"
        "\n"
        "  Email -f1 x@example.local  \n"
        "! bang comment\n"
        "// slash comment\n"
        f"ntp -p 10.0.0.5{nbsp}-s 10.0.0.6 {lquote}q{rquote}\n"
    )
    assert runner.parse_commands(text) == [
        "tcpip -d example.local",
        "Email -f1 x@example.local",
        'ntp -p 10.0.0.5 -s 10.0.0.6 "q"',
    ]


def test_parse_commands_empty(runner):
    assert runner.parse_commands("") == []
    assert runner.parse_commands("\n# only\n!\n") == []


# --------------------------------------------------------------------------- device types


def test_default_device_type_is_apc_aos_on_modern_netmiko(runner):
    assert runner.DEFAULT_DEVICE_TYPE in ("apc_aos", "generic")
    assert "apc_aos" in runner.available_device_types()


def test_resolve_device_type_rules(runner):
    assert runner.resolve_device_type("cisco_ios") == "cisco_ios"
    assert runner.resolve_device_type("", "apc_aos") == "apc_aos"
    assert runner.resolve_device_type("", None, "nope", "linux") == "linux"
    assert runner.resolve_device_type("") == "generic"
    with pytest.raises(ValueError, match="Unknown netmiko device_type"):
        runner.resolve_device_type("apc_nope")


def test_spec_validation(runner):
    with pytest.raises(ValueError):
        runner.SessionSpec(host="h", username="u", password="p", commands=[], send_method="bogus")
    with pytest.raises(Exception):  # noqa: B017 - re.error
        runner.SessionSpec(host="h", username="u", password="p", commands=[], error_pattern="(")
    with pytest.raises(ValueError):
        runner.SessionSpec(host="h", username="u", password="p", commands=[], pause_seconds=-1)


# --------------------------------------------------------------------------- sessions


def test_happy_path_apc_aos_logs_sending_and_response(runner, apc):
    cmds = ["tcpip -d example.local", "Email -f1 apc-lab-1@example.local", "ntp -p 10.0.0.5 -s 10.0.0.6"]
    cap = Capture(runner)
    result = runner.run_session(base_spec(runner, apc, commands=cmds), cap.logger)

    assert result.connected and result.ok
    assert result.prompt == "apc>"
    assert result.device_type == "apc_aos"
    assert [c.command for c in result.commands] == cmds
    assert all(c.response == "E000: Success" and c.ok for c in result.commands)
    assert apc.received == cmds

    infos = cap.messages("info")
    assert "sending: tcpip -d example.local" in infos
    assert "response: E000: Success" in infos
    assert infos.index("sending: tcpip -d example.local") < infos.index("response: E000: Success")
    assert "sending: tcpip -d example.local\nresponse: E000: Success" in result.transcript
    assert "Network Management Card AOS" in result.raw_session_log  # banner captured
    assert not cap.messages("error")


def test_pause_between_commands_is_honoured(runner, apc):
    cmds = ["about", "about", "about"]
    result = runner.run_session(base_spec(runner, apc, commands=cmds, pause_seconds=0.6), None)
    assert result.ok
    # two pauses between three commands
    assert result.duration >= 1.2


def test_error_pattern_marks_failure_and_stops(runner, apc):
    cmds = ["dns -p 1.1.1.1", "Email -t1 bogus", "ntp -p 2.2.2.2"]
    cap = Capture(runner)
    result = runner.run_session(
        base_spec(runner, apc, commands=cmds, error_pattern=APC_ERROR_PATTERN, stop_on_error=True), cap.logger
    )
    assert result.connected and not result.ok
    assert result.sent == 2 and result.failed == 1
    assert result.commands[1].response == "E102: Parameter Error"
    assert "matched error pattern" in result.commands[1].error
    assert apc.received == cmds[:2]
    assert any("skipping remaining 1 command" in m for m in cap.messages("warning"))
    assert "response: E102: Parameter Error" in cap.messages("error")


def test_error_pattern_can_continue(runner, apc):
    cmds = ["frobnicate", "ntp -p 2.2.2.2"]
    result = runner.run_session(
        base_spec(runner, apc, commands=cmds, error_pattern=APC_ERROR_PATTERN, stop_on_error=False), None
    )
    assert result.sent == 2 and result.failed == 1 and not result.ok
    assert result.commands[0].response == "E101: Command Not Found"
    assert result.commands[1].ok


def test_without_error_pattern_everything_is_ok(runner, apc):
    result = runner.run_session(base_spec(runner, apc, commands=["frobnicate"]), None)
    assert result.ok and result.commands[0].response == "E101: Command Not Found"


def test_command_timeout(runner, apc):
    cap = Capture(runner)
    result = runner.run_session(base_spec(runner, apc, commands=["slow", "about"], command_timeout=1.5), cap.logger)
    assert result.connected and not result.ok
    assert result.sent == 1 and result.failed == 1
    assert "no prompt within 1.5s" in result.commands[0].error
    assert apc.received == ["slow"]


def test_dry_run_connects_but_sends_nothing(runner, apc):
    cap = Capture(runner)
    result = runner.run_session(base_spec(runner, apc, commands=["dns -p 1.1.1.1", "about"], dry_run=True), cap.logger)
    assert result.connected and result.ok and result.dry_run
    assert result.sent == 0
    assert result.prompt == "apc>"
    assert apc.received == []
    assert any("would send: dns -p 1.1.1.1" in m for m in cap.messages("info"))


@pytest.mark.parametrize("send_method", ["prompt", "timing"])
def test_generic_driver_both_send_methods(runner, apc, send_method):
    result = runner.run_session(
        base_spec(runner, apc, commands=["dns -p 1.1.1.1", "about"], device_type="generic", send_method=send_method),
        None,
    )
    assert result.ok and result.prompt == "apc>"
    assert [c.response for c in result.commands] == ["E000: Success", "E000: Success"]


def test_bad_password_is_reported_and_never_logged(runner, apc):
    cap = Capture(runner)
    result = runner.run_session(base_spec(runner, apc, password="s3cretXYZ-wrong"), cap.logger)
    assert not result.connected and not result.ok
    assert "authentication failed" in result.error
    blob = result.transcript + result.raw_session_log + "\n".join(cap.messages())
    assert "s3cretXYZ-wrong" not in blob


def test_connection_refused(runner):
    result = runner.run_session(
        runner.SessionSpec(
            host="127.0.0.1", port=1, username="u", password="p", commands=["about"], conn_timeout=2, connect_retries=0
        ),
        None,
    )
    assert not result.connected and "connection failed" in result.error


def test_logout_command_is_sent(runner, apc):
    result = runner.run_session(base_spec(runner, apc, commands=["about"], logout_command="exit"), None)
    assert result.ok
    assert apc.received == ["about", "exit"]
    assert apc.exec_requests == 0  # interactive shell only, like a real NMC


def test_long_response_is_truncated_in_log_but_not_transcript(runner, apc):
    apc.responses["dir"] = "x" * 500
    cap = Capture(runner)
    result = runner.run_session(base_spec(runner, apc, commands=["dir"], max_log_chars=100), cap.logger)
    assert result.ok
    logged = next(m for m in cap.messages("info") if m.startswith("response:"))
    assert "truncated 400 chars" in logged
    assert "x" * 500 in result.transcript


def test_scrub_masks_long_secrets_only(runner):
    assert runner._scrub("pw=hunter2hunter2 ok", "hunter2hunter2") == "pw=******** ok"
    assert runner._scrub("apc_aos apc", "apc") == "apc_aos apc"


def test_warning_pattern_marks_but_does_not_fail(runner, apc):
    apc.responses["ntp"] = "E002: Reboot required for change to take effect"
    cap = Capture(runner)
    result = runner.run_session(
        base_spec(
            runner,
            apc,
            commands=["ntp -p 1.1.1.1", "about"],
            error_pattern=APC_ERROR_PATTERN,
            warning_pattern=r"^E002:",
        ),
        cap.logger,
    )
    assert result.ok and result.sent == 2 and result.failed == 0 and result.warned == 1
    assert result.commands[0].warning and not result.commands[1].warning
    assert "response: E002: Reboot required for change to take effect" in cap.messages("warning")
    assert any("matched warning pattern" in m for m in cap.messages("warning"))


def test_unexpected_disconnect_is_a_failure(runner, apc):
    # the fake server closes the session on "reboot"
    result = runner.run_session(base_spec(runner, apc, commands=["reboot", "about"], send_method="timing"), None)
    assert result.connected and not result.ok
    assert result.sent == 1 and "connection closed by the device" in result.commands[0].error
    assert "connection closed by the device" in result.error


def test_expected_disconnect_on_last_command(runner, apc):
    cap = Capture(runner)
    result = runner.run_session(
        base_spec(runner, apc, commands=["about", "reboot"], send_method="timing", disconnect_ok_on_last_command=True),
        cap.logger,
    )
    assert result.ok and result.sent == 2 and result.failed == 0 and not result.error
    assert any("closed by the device after the last command (expected)" in m for m in cap.messages("info"))


def test_negotiation_failure_is_classified_with_hint(runner, monkeypatch):
    from netmiko.exceptions import NetmikoTimeoutException

    def boom(**kwargs):
        raise NetmikoTimeoutException(
            "A paramiko SSHException occurred during connection creation: "
            "Incompatible ssh peer (no acceptable host key)"
        )

    monkeypatch.setattr(runner, "ConnectHandler", boom)
    result = runner.run_session(
        runner.SessionSpec(host="h", username="u", password="p", commands=["x"], connect_retries=0), None
    )
    assert not result.connected
    assert result.error.startswith("SSH negotiation failed")
    support = runner.legacy_ssh_support()
    if not support["ssh-rsa"]:
        assert "paramiko<5" in result.error


def test_prompt_timeout_at_login_is_explained(runner, monkeypatch):
    from netmiko.exceptions import ReadTimeout

    def boom(**kwargs):
        raise ReadTimeout("Pattern not detected: '>' in output.")

    monkeypatch.setattr(runner, "ConnectHandler", boom)
    result = runner.run_session(
        runner.SessionSpec(host="h", username="u", password="p", commands=["x"], connect_retries=0), None
    )
    assert not result.connected
    assert "no CLI prompt appeared" in result.error and "new password" in result.error


def test_normalise_commands_reports_what_it_changed(runner):
    text = "dns -p 10.0.0.1 " + chr(0x2013) + " primary\nntp" + chr(0x200B) + " -p 10.0.0.2\n\u00e9cho\n"
    commands, notes = runner.normalise_commands(text)
    assert commands == ["dns -p 10.0.0.1 - primary", "ntp -p 10.0.0.2", "\u00e9cho"]
    assert any("U+2013" in n for n in notes)
    assert any("U+200B" in n for n in notes)
    assert any("non-ASCII" in n and "U+00E9" in n for n in notes)


def test_success_pattern_flags_unexpected_responses(runner, apc):
    apc.responses["about"] = "Model: Smart-UPS 1500\nSerial: AS1234567890"
    result = runner.run_session(
        base_spec(
            runner, apc, commands=["about", "dns -p 1.1.1.1"], success_pattern=r"^E00[012]:", stop_on_error=False
        ),
        None,
    )
    assert result.sent == 2 and result.failed == 1
    assert "did not match success pattern" in result.commands[0].error
    assert result.commands[1].ok


def test_connect_retries_then_succeeds(runner, apc, monkeypatch):
    from netmiko.exceptions import NetmikoTimeoutException

    real = runner.ConnectHandler
    calls = {"n": 0}

    def flaky(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise NetmikoTimeoutException("TCP connection to device failed.")
        return real(**kwargs)

    monkeypatch.setattr(runner, "ConnectHandler", flaky)
    cap = Capture(runner)
    result = runner.run_session(
        base_spec(runner, apc, commands=["about"], connect_retries=1, retry_backoff=0.1), cap.logger
    )
    assert result.ok and calls["n"] == 2
    assert any("attempt 1/2 failed" in m for m in cap.messages("warning"))


def test_connect_does_not_retry_auth_failures(runner, apc, monkeypatch):
    real = runner.ConnectHandler
    calls = {"n": 0}

    def counting(**kwargs):
        calls["n"] += 1
        return real(**kwargs)

    monkeypatch.setattr(runner, "ConnectHandler", counting)
    result = runner.run_session(
        base_spec(runner, apc, password="definitely-wrong", connect_retries=3, retry_backoff=0.1), None
    )
    assert not result.connected and "authentication failed" in result.error
    assert calls["n"] == 1


def test_verify_login(runner, apc):
    cap = Capture(runner)
    ok, error = runner.verify_login(base_spec(runner, apc, commands=[], logout_command="exit"), cap.logger)
    assert ok and error == ""
    assert any("re-login OK" in m for m in cap.messages("info"))
    assert apc.received == ["exit"]
    ok, error = runner.verify_login(base_spec(runner, apc, commands=[], password="nope"), None)
    assert not ok and "authentication failed" in error


def test_host_key_is_recorded(runner, apc):
    result = runner.run_session(base_spec(runner, apc, commands=["about"]), None)
    assert result.host_key.startswith("ssh-rsa SHA256:") or result.host_key.startswith("rsa-sha2")
    assert "host key=" in result.transcript


def test_transient_banner_error_is_retried_without_legacy_hint(runner, monkeypatch):
    from netmiko.exceptions import NetmikoTimeoutException

    calls = {"n": 0}

    def boom(**kwargs):
        calls["n"] += 1
        raise NetmikoTimeoutException(
            "A paramiko SSHException occurred during connection creation: Error reading SSH protocol banner"
        )

    monkeypatch.setattr(runner, "ConnectHandler", boom)
    result = runner.run_session(
        runner.SessionSpec(host="h", username="u", password="p", commands=["x"], connect_retries=2, retry_backoff=0.05),
        None,
    )
    assert not result.connected and calls["n"] == 3
    assert result.error.startswith("SSH connection failed: Error reading SSH protocol banner")
    assert "paramiko<5" not in result.error


def test_timeout_keeps_device_output(runner, apc):
    from fake_apc_server import NoPrompt

    apc.responses["reboot"] = NoPrompt("Reboot Management Interface? Enter 'YES' to continue or <ENTER> to cancel:")
    cap = Capture(runner)
    result = runner.run_session(base_spec(runner, apc, commands=["reboot"], command_timeout=1.5), cap.logger)
    assert not result.ok and result.failed == 1
    assert "Enter 'YES' to continue" in result.commands[0].response
    assert "Enter 'YES' to continue" in result.transcript


def test_prompt_mode_detects_session_closed_by_device(runner, apc):
    # the fake server closes the session on "reboot"; in prompt mode netmiko only sees a missing prompt
    result = runner.run_session(base_spec(runner, apc, commands=["about", "reboot"], command_timeout=1.5), None)
    assert not result.ok and "connection closed by the device" in result.error
    result = runner.run_session(
        base_spec(runner, apc, commands=["about", "reboot"], command_timeout=1.5, disconnect_ok_on_last_command=True),
        None,
    )
    assert result.ok and result.failed == 0


def test_short_secret_values_are_masked(runner, apc):
    result = runner.run_session(
        base_spec(
            runner,
            apc,
            commands=["radius -s1 ab1"],
            display_commands=["radius -s1 {{ secret('x') }}"],
            mask_values=["ab1"],
        ),
        None,
    )
    assert "ab1" not in result.transcript and "ab1" not in result.raw_session_log
    assert apc.received == ["radius -s1 ab1"]


def test_spec_repr_hides_credentials(runner):
    spec = runner.SessionSpec(host="h", username="u", password="hunter2hunter2", secret="enable-me", commands=["x"])
    assert "hunter2hunter2" not in repr(spec) and "enable-me" not in repr(spec)


# --------------------------------------------------------------------------- other vendors, prompt mode


def shell_spec(runner, server, device_type, commands, **overrides):
    params = dict(
        host=server.host,
        port=server.port,
        username="apc",
        password="apc",
        label="shell",
        device_type=device_type,
        commands=commands,
        pause_seconds=0,
        conn_timeout=10,
        command_timeout=6,
        connect_retries=0,
        logout_command="exit",
    )
    params.update(overrides)
    return runner.SessionSpec(**params)


def test_prompt_regex_derivation(runner):
    import re

    assert re.search(runner.prompt_regex("Switch#"), "Switch(config)#")
    assert re.search(runner.prompt_regex("Switch#"), "Switch(config-if)#")
    assert re.search(runner.prompt_regex("Switch#"), "...\nSwitch#")
    assert not re.search(runner.prompt_regex("Switch#"), "hostname Switch\n")
    assert re.search(runner.prompt_regex("[root@esxi:~]"), "[root@esxi:~] ")
    assert not re.search(runner.prompt_regex("[root@esxi:~]"), "[root@esxi:/tmp] ")
    assert re.search(runner.prompt_regex("apc>"), "apc>")


def test_cisco_ios_config_mode_in_prompt_mode(runner):
    from fake_shells import FakeIOSXE

    cmds = ["conf t", "restconf", "netconf-yang", "end", "write mem", "show run | include restconf|netconf"]
    with FakeIOSXE(name="sw1") as sw:
        result = runner.run_session(shell_spec(runner, sw, "cisco_ios", cmds, error_pattern=r"^%"), None)
        assert result.ok and result.sent == 6 and result.prompt == "Switch#"
        assert sw.config == ["restconf", "netconf-yang"]
        assert result.commands[0].response.startswith("Enter configuration commands")
        assert result.commands[4].response == "Building configuration...\n[OK]"  # attributed to write mem itself
        assert result.commands[5].response == "restconf\nnetconf-yang"


def test_cisco_nxos_config_mode_in_prompt_mode(runner):
    from fake_shells import FakeNXOS

    cmds = ["conf t", "feature nxapi", "end", "copy running-config startup-config", "show feature | include nxapi"]
    with FakeNXOS(name="n9k") as sw:
        result = runner.run_session(shell_spec(runner, sw, "cisco_nxos", cmds, error_pattern=r"^%"), None)
        assert result.ok and result.sent == 5
        assert result.commands[3].response.endswith("Copy complete.")
        assert "enabled" in result.commands[4].response


def test_esxi_shell_needs_generic_driver_and_keeps_its_bracket_prompt(runner):
    from fake_shells import FakeESXi

    cmds = ["esxcli system settings advanced list -o /UserVars/ESXiShellTimeOut", "vim-cmd hostsvc/enable_ssh", "ls"]
    with FakeESXi(name="esx") as esx:
        result = runner.run_session(shell_spec(runner, esx, "generic", cmds, error_pattern=r"not found"), None)
        assert result.ok and result.sent == 3 and result.prompt == "[root@esxi01:~]"
        assert result.commands[0].response.startswith("Path: /UserVars/ESXiShellTimeOut")
        assert result.commands[2].response == "altbootbank  bin  bootbank  dev  etc  lib  tmp  vmfs"


def test_cwd_prompts_need_an_operator_prompt_pattern(runner):
    from fake_shells import FakeESXi, FakeProxmox

    with FakeESXi(name="esx") as esx:
        result = runner.run_session(shell_spec(runner, esx, "generic", ["cd /tmp", "ls"]), None)
        assert not result.ok and "no prompt within" in result.commands[0].error  # derived pattern no longer matches
    with FakeESXi(name="esx") as esx:
        result = runner.run_session(
            shell_spec(runner, esx, "generic", ["cd /tmp", "ls"], prompt_pattern=r"\[root@\S+\] $"), None
        )
        assert result.ok and result.commands[0].response == ""
        assert result.commands[1].response == "altbootbank  bin  bootbank  dev  etc  lib  tmp  vmfs"
    with FakeProxmox(name="pve") as pve:
        result = runner.run_session(
            shell_spec(runner, pve, "linux", ["cd /etc/pve", "cat datacenter.cfg"], prompt_pattern=r"root@\S+#\s*$"),
            None,
        )
        assert result.ok
        assert result.commands[1].response == "# datacenter config\nkeyboard: en-us\n# end of file\nmigration: secure"


def test_proxmox_linux_driver(runner):
    from fake_shells import FakeProxmox

    cmds = ["pvesh get /version --output-format json", "systemctl restart pveproxy", "cat datacenter.cfg"]
    with FakeProxmox(name="pve") as pve:
        result = runner.run_session(shell_spec(runner, pve, "linux", cmds, error_pattern=r"command not found"), None)
        assert result.ok and result.sent == 3 and result.prompt == "root@pve1:~#"
        assert result.commands[0].response.startswith('{"release":"8.3"')
        assert result.commands[2].response.startswith("# datacenter config")


# --------------------------------------------------------------------------- legacy SHA-1 algorithms (paramiko 5)

LEGACY_KEX = ("diffie-hellman-group14-sha1",)


def test_legacy_shim_is_reverted_after_use(runner):
    import sys

    legacy = sys.modules["legacy_ssh"]
    from paramiko.transport import Transport

    before_kex, before_keys = Transport._preferred_kex, Transport._preferred_keys
    missing = legacy.legacy_algorithms_missing()
    with legacy.legacy_algorithms() as active:
        assert active == bool(missing)
        if active:
            assert "ssh-rsa" in Transport._preferred_keys and Transport._preferred_keys[0] != "ssh-rsa"
            assert Transport._preferred_kex[-3:] == tuple(k.name for k in legacy.LEGACY_KEX)
            with legacy.legacy_algorithms():  # re-entrant
                pass
            assert "ssh-rsa" in Transport._key_info
    assert Transport._preferred_kex == before_kex and Transport._preferred_keys == before_keys
    assert legacy.legacy_algorithms_missing() == missing


def test_legacy_only_server_needs_the_shim(runner):
    import sys

    from fake_apc_server import FakeApcServer

    legacy = sys.modules["legacy_ssh"]
    if not legacy.legacy_algorithms_missing():
        pytest.skip("installed paramiko still ships the SHA-1 algorithms")
    # the fake server is paramiko too, so it can only *offer* the legacy algorithms while the shim is active
    # (which also patches the client in this process; the negative case is covered against real OpenSSH below)
    with legacy.legacy_algorithms(), FakeApcServer(kex_algorithms=LEGACY_KEX, key_types=("ssh-rsa",)) as apc:
        cap = Capture(runner)
        result = runner.run_session(base_spec(runner, apc, commands=["about"], legacy_ssh_algorithms=True), cap.logger)
        assert result.ok and result.host_key.startswith("ssh-rsa SHA256:")  # SHA-1 signature verified
        ok, error = runner.verify_login(base_spec(runner, apc, commands=[], legacy_ssh_algorithms=True), None)
        assert ok, error


@pytest.mark.skipif(
    not os.environ.get("LEGACY_SSHD"),
    reason="set LEGACY_SSHD=host:port to an OpenSSH server offering only ssh-rsa + SHA-1 kex",
)
def test_legacy_shim_against_real_openssh(runner):
    import sys

    host, port = os.environ["LEGACY_SSHD"].rsplit(":", 1)

    def spec(flag):
        return runner.SessionSpec(
            host=host,
            port=int(port),
            username="apc",
            password="apc",
            device_type="linux",
            commands=["echo ok"],
            connect_retries=0,
            legacy_ssh_algorithms=flag,
        )

    if sys.modules["legacy_ssh"].legacy_algorithms_missing():
        result = runner.run_session(spec(False), None)
        assert not result.connected and "SSH negotiation failed" in result.error
        assert "Allow SHA-1 SSH algorithms" in result.error
    result = runner.run_session(spec(True), None)
    assert result.ok and result.commands[0].response == "ok" and result.host_key.startswith("ssh-rsa ")


# --------------------------------------------------------------------------- real-NMC echo styles

NMC_CMDS = [
    "tcpip -d example.local",
    "dns -p 10.0.0.3 -s 10.0.0.4 -d example.local",
    "ntp -p 10.0.0.5 -s 10.0.0.6",
    "about",
]


@pytest.mark.parametrize(
    "variant",
    [
        {},  # prompt + echo in one chunk
        {"split_delay": 0.5},  # prompt re-printed, echo arrives half a second later
        {"echo": False},  # the card does not echo at all
        {"wrap": 24},  # echo wrapped at the terminal width
    ],
    ids=["one-chunk", "split-echo", "no-echo", "wrapped-echo"],
)
@pytest.mark.parametrize("method", ["prompt", "timing"])
def test_nmc_echo_styles_give_clean_responses(runner, variant, method):
    from fake_shells import FakeNMCEcho

    with FakeNMCEcho(name="nmc2", **variant) as nmc:
        cap = Capture(runner)
        result = runner.run_session(
            shell_spec(
                runner,
                nmc,
                "apc_aos",
                NMC_CMDS,
                send_method=method,
                error_pattern=r"^E1\d{2}:",
                success_pattern=r"^E00[012]:",
            ),
            cap.logger,
        )
        assert result.ok, [c.error for c in result.commands]
        assert [c.response for c in result.commands] == ["E000: Success"] * 4
        assert nmc.received == [*NMC_CMDS, "exit"]
        if method == "prompt" and variant.get("echo") is False:
            assert any("no recognisable echo" in m for m in cap.messages("info"))


def test_clean_response_helper(runner):
    expect = runner.prompt_regex("apc>")
    assert (
        runner.clean_response("apc>dns -p 1.1.1.1\nE000: Success\n\napc>", "dns -p 1.1.1.1", expect) == "E000: Success"
    )
    assert runner.clean_response("\napc>\nE000: Success\napc>", "about", expect) == "E000: Success"
    assert runner.clean_response("line1\nline2\n", "x", expect) == "line1\nline2"
    assert runner.clean_response("", "x", expect) == ""
    assert runner.clean_response("Switch(config)#", "conf t", runner.prompt_regex("Switch#")) == ""
    wrapped = "apc>dns -p 10.0.0.3 -s 10.0.\n0.4 -d example.local\nE000: Success\n\napc>"
    assert runner.clean_response(wrapped, "dns -p 10.0.0.3 -s 10.0.0.4 -d example.local", expect) == "E000: Success"
    assert (
        runner.clean_response("E000: Success", "dns", expect) == "E000: Success"
    )  # response starting like the command
