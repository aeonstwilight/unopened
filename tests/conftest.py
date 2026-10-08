"""Test-wide safety guards.

Rule 1 (never execute a sample) and rule 3 (no network by default) are enforced
mechanically: for the whole test session any attempt to open a network connection or
start a process fails the test. Analyzer workers are forked, so they inherit the guards.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import build  # noqa: E402


class ForbiddenCall(AssertionError):
    pass


def _forbid(what: str):
    def guard(*args, **kwargs):
        raise ForbiddenCall(f"{what} is forbidden during tests (static analysis only, no network)")

    return guard


@pytest.fixture(autouse=True, scope="session")
def no_network_no_processes():
    mp = pytest.MonkeyPatch()
    mp.setattr(socket.socket, "connect", _forbid("socket.connect"))
    mp.setattr(socket.socket, "connect_ex", _forbid("socket.connect_ex"))
    mp.setattr(socket.socket, "sendto", _forbid("socket.sendto"))
    mp.setattr(socket, "create_connection", _forbid("socket.create_connection"))
    mp.setattr(socket, "getaddrinfo", _forbid("DNS resolution"))
    mp.setattr(subprocess.Popen, "__init__", _forbid("subprocess.Popen"))
    for name in ("system", "popen", "posix_spawn", "posix_spawnp", "execv", "execve", "execvp",
                 "execvpe", "execl", "execle", "execlp", "execlpe", "spawnv", "spawnve",
                 "startfile"):
        if hasattr(os, name):
            mp.setattr(os, name, _forbid(f"os.{name}"))
    yield
    mp.undo()


@pytest.fixture
def make_file(tmp_path):
    def make(name: str, data: bytes) -> Path:
        path = tmp_path / name
        path.write_bytes(data)
        return path

    return make


@pytest.fixture
def fixtures():
    return build


@pytest.fixture
def office_fx():
    from fixtures import office

    return office


@pytest.fixture
def lnk_fx():
    from fixtures import lnk

    return lnk


@pytest.fixture
def arch_fx():
    from fixtures import archives

    return archives
