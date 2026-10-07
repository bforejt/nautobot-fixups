"""Nautobot Jobs provided by this repository."""

from nautobot.apps.jobs import register_jobs

from .ssh_fixup_engine import SSHFixupEngine

register_jobs(SSHFixupEngine)
