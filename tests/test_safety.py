"""The guards in conftest.py work, and the source tree contains no code that could run
a sample or reach the network."""

from __future__ import annotations

import ast
import socket
import subprocess
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "unopened"

FORBIDDEN_MODULES = {
    "subprocess", "socket", "ctypes", "cffi", "urllib.request", "http.client", "requests",
    "httpx", "aiohttp", "ftplib", "smtplib", "telnetlib", "runpy", "pickle", "marshal",
    "webbrowser", "pty", "code", "codeop",
}
NETWORK_MODULES = {"socket", "urllib.request", "http.client", "ssl"}
# The single place allowed to talk to the network (opt-in reputation lookups, rule 3).
NETWORK_ALLOWED = {"reputation/transport.py"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_ATTRS = {
    ("os", "system"), ("os", "popen"), ("os", "startfile"), ("os", "posix_spawn"),
    ("os", "posix_spawnp"), ("os", "execv"), ("os", "execve"), ("os", "execvp"),
    ("importlib", "import_module"),
}


def test_network_is_blocked():
    with pytest.raises(AssertionError, match="forbidden"):
        socket.create_connection(("192.0.2.1", 80))


def test_processes_are_blocked():
    with pytest.raises(AssertionError, match="forbidden"):
        subprocess.Popen(["true"])


def python_files():
    files = sorted(SRC.rglob("*.py"))
    assert files, "source tree not found"
    return files


@pytest.mark.parametrize("path", python_files(), ids=lambda p: str(p.relative_to(SRC)))
def test_source_has_no_execution_or_network_primitives(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    rel = path.relative_to(SRC).as_posix()
    forbidden = FORBIDDEN_MODULES - (NETWORK_MODULES if rel in NETWORK_ALLOWED else set())
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            names = []
        for name in names:
            if any(name == m or name.startswith(m + ".") for m in forbidden):
                problems.append(f"line {node.lineno}: imports {name}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in FORBIDDEN_CALLS:
                problems.append(f"line {node.lineno}: calls {node.func.id}()")
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if (node.value.id, node.attr) in FORBIDDEN_ATTRS:
                problems.append(f"line {node.lineno}: uses {node.value.id}.{node.attr}")
    assert not problems, f"{path.name}: " + "; ".join(problems)


def test_network_module_is_the_only_exception():
    assert NETWORK_ALLOWED == {"reputation/transport.py"}
    assert (SRC / "reputation" / "transport.py").exists()


def test_triage_without_reputation_never_imports_the_network_module(make_file, fixtures):
    import sys

    from unopened import pipeline
    from unopened.analyzers import Options

    sys.modules.pop("unopened.reputation.transport", None)
    sys.modules.pop("unopened.reputation", None)
    pipeline.triage(make_file("a.exe", fixtures.benign_exe()), Options(), isolate=False)
    assert "unopened.reputation.transport" not in sys.modules
    assert "unopened.reputation" not in sys.modules
