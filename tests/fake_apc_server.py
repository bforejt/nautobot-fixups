"""A tiny paramiko-based SSH server that imitates an APC Network Management Card CLI.

Used only by the test-suite (and handy for manual experiments). It is deliberately
simple: password auth, an interactive shell with a banner, an ``apc>`` prompt, local
echo, and canned responses in the APC style (``E000: Success`` / ``E101: Command Not
Found`` ...). It records every command line it receives so tests can assert on them.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Union

import paramiko

BANNER_TEMPLATE = (
    "American Power Conversion               Network Management Card AOS      v6.9.6\r\n"
    "(c) Copyright 2021 All Rights Reserved  Smart-UPS APP                    v6.9.6\r\n"
    "-------------------------------------------------------------------------------\r\n"
    "Name      : {name:<36} Date : 10/07/2026\r\n"
    "Contact   : Unknown                              Time : 12:00:00\r\n"
    "Location  : Unknown                              User : Administrator\r\n"
    "Up Time   : 0 Days 1 Hours 2 Minutes             Stat : P+ N4+ N6+ A+\r\n"
    "\r\n"
    "Type ? for command listing\r\n"
    "Use tcpip command for IP address(-i), subnet(-s), and gateway(-g)\r\n"
    "\r\n"
)
PROMPT = "apc>"


class NoPrompt(str):
    """A canned response after which the fake card does NOT print the prompt (interactive confirmations)."""


ResponseType = Union[str, Callable[[str], str]]


@dataclass
class FakeApcServer:
    """Threaded fake APC NMC SSH server bound to 127.0.0.1 on an ephemeral port."""

    username: str = "apc"
    password: str = "apc"
    name: str = "fake-apc"
    response_delay: float = 0.0
    # first token (lower-cased) -> canned response, or callable(line) -> response
    responses: dict[str, ResponseType] = field(default_factory=dict)
    received: list[str] = field(default_factory=list)
    sessions_opened: int = 0
    exec_requests: int = 0

    _sock: socket.socket | None = None
    _thread: threading.Thread | None = None
    _stop: threading.Event = field(default_factory=threading.Event)
    _host_key: paramiko.PKey | None = None
    _port: int = 0

    # ------------------------------------------------------------------ lifecycle
    def __enter__(self) -> FakeApcServer:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    @property
    def port(self) -> int:
        return self._port

    @property
    def host(self) -> str:
        return "127.0.0.1"

    def start(self) -> None:
        self._host_key = paramiko.RSAKey.generate(2048)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self._port = self._sock.getsockname()[1]
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop, name="fake-apc-accept", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------------ internals
    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                client, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        transport = paramiko.Transport(client)
        try:
            transport.add_server_key(self._host_key)
            iface = _ServerInterface(self)
            transport.start_server(server=iface)
            chan = transport.accept(20)
            if chan is None:
                return
            if not iface.shell_event.wait(10):
                return
            self.sessions_opened += 1
            self._shell(chan)
        except Exception:
            pass
        finally:
            try:
                transport.close()
            except Exception:
                pass

    def _respond(self, line: str) -> str | None:
        """Return the response text for one command line, or None to close the session."""
        stripped = line.strip()
        if not stripped:
            return ""
        token = stripped.split()[0].lower()
        if token in ("exit", "quit", "bye"):
            return None
        handler = self.responses.get(token)
        if handler is not None:
            return handler(stripped) if callable(handler) else handler
        if token in ("?", "help"):
            return (
                "System Commands:\r\n"
                "---------------------------------------------------------------------------\r\n"
                "For command help: command ?\r\n\r\n"
                "?            about        alarmcount   boot         bye          cd\r\n"
                "console      date         delete       dir          dns          email\r\n"
                "exit         ntp          ping         quit         radius       reboot\r\n"
                "system       tcpip        user"
            )
        if token == "slow":
            time.sleep(3.0)
            return "E000: Success"
        if token == "reboot":
            return None
        known = {"tcpip", "email", "radius", "dns", "ntp", "system", "about", "date", "user", "snmp", "web", "ping"}
        if token in known:
            if "bogus" in stripped.lower():
                return "E102: Parameter Error"
            return "E000: Success"
        return "E101: Command Not Found"

    def _shell(self, chan: paramiko.Channel) -> None:
        chan.settimeout(30)
        chan.sendall((BANNER_TEMPLATE.format(name=self.name) + PROMPT).encode())
        buf = ""
        while not self._stop.is_set():
            try:
                data = chan.recv(1024)
            except socket.timeout:
                continue
            except Exception:
                break
            if not data:
                break
            text = data.decode(errors="replace")
            for ch in text:
                if ch in ("\r", "\n"):
                    # a bare "\r\n" pair should only trigger one line
                    if ch == "\n" and buf == "" and getattr(self, "_last_was_cr", False):
                        self._last_was_cr = False
                        continue
                    self._last_was_cr = ch == "\r"
                    chan.sendall(b"\r\n")
                    line, buf = buf, ""
                    if line.strip():
                        self.received.append(line)
                    if self.response_delay:
                        time.sleep(self.response_delay)
                    response = self._respond(line)
                    if response is None:
                        chan.sendall(b"Bye.\r\n")
                        chan.close()
                        return
                    if response:
                        chan.sendall((response + "\r\n\r\n").encode())
                    if not isinstance(response, NoPrompt):
                        chan.sendall(PROMPT.encode())
                elif ch in ("\x7f", "\b"):
                    if buf:
                        buf = buf[:-1]
                        chan.sendall(b"\b \b")
                else:
                    self._last_was_cr = False
                    buf += ch
                    chan.sendall(ch.encode())  # local echo, like a pty


class _ServerInterface(paramiko.ServerInterface):
    def __init__(self, owner: FakeApcServer) -> None:
        self.owner = owner
        self.shell_event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        if username == self.owner.username and password == self.owner.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.shell_event.set()
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        # Real NMCs do not run commands via the SSH exec channel; neither do we.
        self.owner.exec_requests += 1
        return False


if __name__ == "__main__":  # manual experimentation: python tests/fake_apc_server.py
    with FakeApcServer() as srv:
        print(f"fake APC listening on {srv.host}:{srv.port} (user apc / pass apc) - Ctrl-C to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
