"""Pytest fixtures: load the runner by path (no Nautobot/Django needed) and start the fake APC server."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))


def _load_by_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_runner():
    """Import jobs/ssh_runner.py directly so importing ``jobs`` (which needs Nautobot) is not required."""
    if "ssh_runner" in sys.modules:
        return sys.modules["ssh_runner"]
    if "legacy_ssh" not in sys.modules:  # the runner falls back to a plain import of this module
        _load_by_path("legacy_ssh", REPO_ROOT / "jobs" / "legacy_ssh.py")
    spec = importlib.util.spec_from_file_location("ssh_runner", REPO_ROOT / "jobs" / "ssh_runner.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ssh_runner"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def runner():
    return _load_runner()


@pytest.fixture
def apc():
    from fake_apc_server import FakeApcServer

    with FakeApcServer(name="apc-lab-1") as server:
        yield server
