"""Fake shells with mode-dependent prompts (IOS-XE, NX-OS, ESXi, Proxmox) on the fake APC server transport.

Used by the runner tests to prove the 'prompt' send method copes with config modes and odd prompts.
"""

from __future__ import annotations

import time

import fake_apc_server as base


class FakeShell(base.FakeApcServer):
    banner = "\r\n"

    def __init__(self, **kw):
        super().__init__(**kw)
        self.mode = "exec"
        self.cwd = "~"
        self.config = []

    def _prompt(self):
        raise NotImplementedError

    def _shell(self, chan):
        chan.settimeout(30)
        chan.sendall(self.banner.encode() + self._prompt().encode())
        buf = ""
        while not self._stop.is_set():
            try:
                data = chan.recv(1024)
            except Exception:
                break
            if not data:
                break
            for ch in data.decode(errors="replace"):
                if ch in ("\r", "\n"):
                    if ch == "\n" and buf == "" and getattr(self, "_last_was_cr", False):
                        self._last_was_cr = False
                        continue
                    self._last_was_cr = ch == "\r"
                    chan.sendall(b"\r\n")
                    line, buf = buf, ""
                    if line.strip():
                        self.received.append(line)
                    response = self._respond(line)
                    if response is None:
                        chan.close()
                        return
                    if response:
                        chan.sendall((response.replace("\n", "\r\n") + "\r\n").encode())
                    chan.sendall(self._prompt().encode())
                else:
                    self._last_was_cr = False
                    buf += ch
                    chan.sendall(ch.encode())


class FakeIOSXE(FakeShell):
    banner = "\r\nUser Access Verification\r\n\r\n"

    def _prompt(self):
        return "Switch#" if self.mode == "exec" else "Switch(config)#"

    def _respond(self, line):
        s = line.strip()
        if not s:
            return ""
        t = s.lower()
        if self.mode == "exec":
            if t in ("exit", "logout", "quit"):
                return None
            if t.startswith("terminal "):
                return ""
            if t in ("conf t", "configure terminal", "config t"):
                self.mode = "config"
                return "Enter configuration commands, one per line.  End with CNTL/Z."
            if t in ("write mem", "write memory", "wr", "copy run start"):
                time.sleep(3.0)  # IOS takes a few seconds here
                return "Building configuration...\n[OK]"
            if t.startswith("show run"):
                return "\n".join(self.config) or "!"
            if t.startswith("show "):
                return "Cisco IOS XE Software, Version 17.09.04a"
            return "% Invalid input detected at '^' marker."
        if t in ("end", "exit"):
            self.mode = "exec"
            return ""
        if t in ("restconf", "netconf-yang", "ip http secure-server") or t.startswith("netconf-yang "):
            self.config.append(s)
            return ""
        return "% Invalid input detected at '^' marker."


class FakeNXOS(FakeShell):
    banner = "\r\nCisco Nexus Operating System (NX-OS) Software\r\n"

    def _prompt(self):
        return "n9k-1#" if self.mode == "exec" else "n9k-1(config)#"

    def _respond(self, line):
        t = line.strip().lower()
        if not t:
            return ""
        if self.mode == "exec":
            if t in ("exit", "logout"):
                return None
            if t.startswith("terminal "):
                return ""
            if t in ("conf t", "configure terminal", "configure"):
                self.mode = "config"
                return "Enter configuration commands, one per line. End with CNTL/Z."
            if t.startswith("copy running-config startup-config") or t == "copy run start":
                time.sleep(3.0)
                return "[########################################] 100%\nCopy complete."
            if t.startswith("show feature"):
                return "nxapi                 1          " + (
                    "enabled" if "feature nxapi" in self.config else "disabled"
                )
            if t.startswith("show "):
                return "  NXOS: version 10.2(5)"
            return "% Invalid command at '^' marker."
        if t in ("end", "exit"):
            self.mode = "exec"
            return ""
        if t.startswith("feature ") or t.startswith("no feature ") or t.startswith("nxapi "):
            self.config.append(t)
            return ""
        return "% Invalid command at '^' marker."


class FakeESXi(FakeShell):
    banner = (
        "\r\nThe time and date of this login have been sent to the system logs.\r\n\r\n"
        "WARNING:\r\n   All commands run on the ESXi shell are logged.\r\n\r\n"
    )

    def _prompt(self):
        return f"[root@esxi01:{self.cwd}] "  # ESXi PS1 ends with '] ' - no '#', '>' or '$'

    def _respond(self, line):
        t = line.strip()
        if not t:
            return ""
        if t in ("exit", "logout"):
            return None
        if t.startswith("cd "):
            self.cwd = t.split(None, 1)[1]
            return ""
        if t.startswith("esxcli system settings advanced list"):
            return (
                "   Path: /UserVars/ESXiShellTimeOut\n   Type: integer\n   Int Value: 0\n   Default Int Value: 0\n"
                "   Description: Time before automatically disabling local and remote shell access (seconds)"
            )
        if t.startswith("esxcli") or t.startswith("vim-cmd"):
            self.config.append(t)
            return ""
        if t == "ls":
            return "altbootbank  bin  bootbank  dev  etc  lib  tmp  vmfs"
        return f"sh: {t.split()[0]}: not found"


class FakeProxmox(FakeShell):
    banner = (
        "\r\nLinux pve1 6.8.12-4-pve #1 SMP PREEMPT_DYNAMIC x86_64\r\n\r\n"
        "Last login: Tue Oct  7 09:00:00 2026 from 10.0.0.5\r\n"
    )

    def _prompt(self):
        return f"root@pve1:{self.cwd}#"

    def _respond(self, line):
        t = line.strip()
        if not t:
            return ""
        if t in ("exit", "logout"):
            return None
        if t.startswith("cd "):
            self.cwd = t.split(None, 1)[1]
            return ""
        if t.startswith("pvesh get /version"):
            return '{"release":"8.3","repoid":"3e76eec21c4a14a7","version":"8.3.0"}'
        if t.startswith("systemctl restart") or t.startswith("pvesh set") or t.startswith("pvesm "):
            self.config.append(t)
            return ""
        if t.startswith("cat datacenter.cfg"):
            return "# datacenter config\nkeyboard: en-us\n# end of file\nmigration: secure"
        return f"-bash: {t.split()[0]}: command not found"


class FakeNMCEcho(base.FakeApcServer):
    """APC NMC with the real card's echo style: no per-character echo; after Enter it prints
    ``\r\napc>`` + the command line (optionally as a later chunk, wrapped, or not at all), then the response."""

    def __init__(self, split_delay=0.0, echo=True, wrap=0, **kw):
        super().__init__(**kw)
        self.split_delay = split_delay  # seconds between "apc>" and the echoed command
        self.echo = echo  # False: the card does not echo the command at all
        self.wrap = wrap  # > 0: echo wrapped at this many columns

    def _shell(self, chan):
        chan.settimeout(30)
        chan.sendall((base.BANNER_TEMPLATE.format(name=self.name) + base.PROMPT).encode())
        buf = ""
        while not self._stop.is_set():
            try:
                data = chan.recv(1024)
            except Exception:
                break
            if not data:
                break
            for ch in data.decode(errors="replace"):
                if ch in ("\r", "\n"):
                    if ch == "\n" and buf == "" and getattr(self, "_last_was_cr", False):
                        self._last_was_cr = False
                        continue
                    self._last_was_cr = ch == "\r"
                    line, buf = buf, ""
                    if line.strip():
                        self.received.append(line)
                    chan.sendall(b"\r\n" + base.PROMPT.encode())  # prompt re-printed first ...
                    if self.split_delay and line.strip():
                        time.sleep(self.split_delay)
                    if self.echo and line:
                        echoed = line
                        if self.wrap:
                            echoed = "\r\n".join(line[i : i + self.wrap] for i in range(0, len(line), self.wrap))
                        chan.sendall(echoed.encode())  # ... then the command echo
                    chan.sendall(b"\r\n")
                    response = self._respond(line)
                    if response is None:
                        chan.sendall(b"Bye.\r\n")
                        chan.close()
                        return
                    if response:
                        chan.sendall((response + "\r\n\r\n").encode())
                    chan.sendall(base.PROMPT.encode())
                else:
                    self._last_was_cr = False
                    buf += ch  # no per-character echo
