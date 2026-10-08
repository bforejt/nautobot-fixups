"""Opt-in SHA-1 SSH algorithms for paramiko 5 (ssh-rsa signatures, SHA-1 Diffie-Hellman).

paramiko 5.0 removed the ``ssh-rsa`` (SHA-1) signature algorithm and the SHA-1 key-exchange
methods. Old network management cards (e.g. APC NMC2 on AOS 6.x/7.x) offer nothing else, so
with paramiko 5 they cannot be reached at all. This module re-adds those algorithms the way
OpenSSH's ``-oHostKeyAlgorithms=+ssh-rsa -oKexAlgorithms=+diffie-hellman-group14-sha1`` does:
appended at the *end* of paramiko's preference lists, so a device that supports anything
modern keeps negotiating the modern algorithm.

The DH math, packet handling and RSA PKCS#1 v1.5 verification are paramiko's own; only the hash
function and the group parameters differ, exactly as in paramiko 4's ``KexGroup1`` /
``KexGroup14`` / ``KexGex`` classes.

Usage::

    with legacy_algorithms():
        conn = ConnectHandler(...)   # negotiates ssh-rsa / group14-sha1 when that is all the peer has
        ...

The patch is process-wide while the context is active and is reverted on exit. On paramiko < 5
(which still ships these algorithms) it is a no-op.
"""

from __future__ import annotations

import contextlib
import threading
from hashlib import sha1

import paramiko
from cryptography.hazmat.primitives import hashes
from paramiko.kex_gex import KexGexSHA256
from paramiko.kex_group14 import KexGroup14SHA256
from paramiko.rsakey import RSAKey
from paramiko.transport import Transport

__all__ = ["LEGACY_KEX", "legacy_algorithms", "legacy_algorithms_missing"]


class KexGroup14SHA1(KexGroup14SHA256):
    """RFC 4253 diffie-hellman-group14-sha1: same 2048-bit group as group14-sha256, SHA-1 hash."""

    name = "diffie-hellman-group14-sha1"
    hash_algo = sha1


class KexGroup1SHA1(KexGroup14SHA256):
    """RFC 4253 diffie-hellman-group1-sha1: the 1024-bit Oakley group 2 (RFC 2409), SHA-1 hash."""

    name = "diffie-hellman-group1-sha1"
    hash_algo = sha1
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF  # noqa: E501
    G = 2


class KexGexSHA1(KexGexSHA256):
    """RFC 4419 diffie-hellman-group-exchange-sha1; old devices may only have 1024-bit groups."""

    name = "diffie-hellman-group-exchange-sha1"
    hash_algo = sha1
    min_bits = 1024


LEGACY_KEX = (KexGroup14SHA1, KexGroup1SHA1, KexGexSHA1)
LEGACY_KEYS = ("ssh-rsa",)

# This module leans on paramiko internals; fail loudly at import time if a future release moves them.
for _attr in ("_kex_info", "_key_info", "_preferred_kex", "_preferred_keys", "_preferred_pubkeys"):
    if not hasattr(Transport, _attr):
        raise ImportError(f"paramiko {paramiko.__version__}: Transport.{_attr} missing; legacy_ssh needs updating")
if not isinstance(getattr(RSAKey, "HASHES", None), dict) or not callable(getattr(KexGroup14SHA256, "start_kex", None)):
    raise ImportError(
        f"paramiko {paramiko.__version__}: RSAKey.HASHES / kex classes changed; legacy_ssh needs updating"
    )
_lock = threading.RLock()
_depth = 0
_saved: dict = {}


def legacy_algorithms_missing() -> list[str]:
    """Names of the legacy algorithms the installed paramiko does not offer (empty on paramiko < 5)."""
    missing = [k.name for k in LEGACY_KEX if k.name not in Transport._kex_info]
    missing += [k for k in LEGACY_KEYS if k not in Transport._key_info]
    return missing


def _apply() -> None:
    global _saved
    _saved = {
        "hashes": dict(RSAKey.HASHES),
        "key_info": dict(Transport._key_info),
        "kex_info": dict(Transport._kex_info),
        "preferred_keys": Transport._preferred_keys,
        "preferred_pubkeys": Transport._preferred_pubkeys,
        "preferred_kex": Transport._preferred_kex,
    }
    RSAKey.HASHES.setdefault("ssh-rsa", hashes.SHA1)
    RSAKey.HASHES.setdefault("ssh-rsa-cert-v01@openssh.com", hashes.SHA1)
    Transport._key_info.setdefault("ssh-rsa", RSAKey)
    Transport._key_info.setdefault("ssh-rsa-cert-v01@openssh.com", RSAKey)
    for kex in LEGACY_KEX:
        Transport._kex_info.setdefault(kex.name, kex)
    # appended, never prepended: modern algorithms stay preferred
    Transport._preferred_keys = tuple(Transport._preferred_keys) + tuple(
        k for k in LEGACY_KEYS if k not in Transport._preferred_keys
    )
    Transport._preferred_pubkeys = tuple(Transport._preferred_pubkeys) + tuple(
        k for k in LEGACY_KEYS if k not in Transport._preferred_pubkeys
    )
    Transport._preferred_kex = tuple(Transport._preferred_kex) + tuple(
        k.name for k in LEGACY_KEX if k.name not in Transport._preferred_kex
    )


def _revert() -> None:
    RSAKey.HASHES.clear()
    RSAKey.HASHES.update(_saved["hashes"])
    Transport._key_info.clear()
    Transport._key_info.update(_saved["key_info"])
    Transport._kex_info.clear()
    Transport._kex_info.update(_saved["kex_info"])
    Transport._preferred_keys = _saved["preferred_keys"]
    Transport._preferred_pubkeys = _saved["preferred_pubkeys"]
    Transport._preferred_kex = _saved["preferred_kex"]


@contextlib.contextmanager
def legacy_algorithms(enabled: bool = True):
    """Re-enable ssh-rsa and SHA-1 DH key exchange in paramiko for the duration of the block.

    Re-entrant; the tables are restored when the outermost block exits. A no-op when ``enabled`` is
    false or the installed paramiko already offers everything (paramiko < 5).
    """
    global _depth
    if not enabled or not legacy_algorithms_missing():
        yield False
        return
    with _lock:
        if _depth == 0:
            _apply()
        _depth += 1
    try:
        yield True
    finally:
        with _lock:
            _depth -= 1
            if _depth == 0:
                _revert()


def paramiko_version() -> str:
    return paramiko.__version__
