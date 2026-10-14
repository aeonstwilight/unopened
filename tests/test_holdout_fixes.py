"""End-to-end regressions for gaps found by the M5 holdout run (real MalwareBazaar samples
the rules had not seen). Every input here is synthetic and harmless: the evidence is
rebuilt from what the reports showed, never from the samples.
"""

from __future__ import annotations

import pytest

from unopened import pipeline
from unopened.analyzers import Options


def triage(path):
    return pipeline.triage(path, Options(hunt=False))


def ids(report):
    return {f.id: f.severity for f in report.findings()}


def test_padded_obfuscated_persistent_powershell(make_file, arch_fx):
    # Run 1: junk padding hid the language, the script analyzer never ran, and once it
    # did, "obfuscated" and "sets up persistence" were two MEDIUMs, one short of suspicious.
    padding = "".join(f"qzx{i} wvk{i * 7} " for i in range(4000)) + "\n"
    payload = ("powershell.exe -NoProfile -EncodedCommand " + arch_fx._ps_b64(
        "Register-ScheduledTask -TaskName upd -Action (New-ScheduledTaskAction "
        "-Execute 'C:\\Users\\Public\\u.exe')") + "\n")
    r = triage(make_file("p.ps1", (padding + payload).encode()))
    assert r.file_type.kind == "script"
    found = ids(r)
    assert "script.obfuscated" in found and "script.ps.persistence" in found
    assert "behavior.obfuscated_persistent_script" in found
    assert r.verdict["value"] in ("suspicious", "malicious")


def test_disk_image_hiding_files_next_to_programs(make_file, arch_fx, fixtures):
    # Run 1: an ISO with 12 programs and 16 hidden files (signed Microsoft DLLs beside a
    # side-loaded one) had two MEDIUM container findings and came back "no findings".
    pytest.importorskip("pycdlib")
    data = arch_fx.iso_image({"Setup.exe": fixtures.benign_exe(),
                              "version.dll": fixtures.benign_dll()}, hidden={"version.dll"})
    r = triage(make_file("kit.iso", data))
    assert ids(r)["behavior.hidden_programs_in_image"].value == "high"
    assert r.verdict["value"] == "suspicious"


def test_msi_contents_are_reported_as_not_checked(make_file, office_fx):
    # Run 1: two MSI installers came back "no findings" without saying their contents were
    # never examined.
    r = triage(make_file("setup.msi", office_fx.msi_like()))
    assert r.file_type.subtype == "msi"
    assert any(n.check == pipeline.MSI_NOT_CHECKED for n in r.not_checked)
    assert r.verdict["value"] == "no findings"
    assert r.verdict["confidence"] == "low"
    assert any("Windows Installer" in c for c in r.verdict["caveats"])


def _pump_options():
    from unopened.extraction import Limits
    return Options(hunt=False, limits=Limits(max_member_size=50_000))


def test_pumped_program_in_7z_is_called_out(make_file, arch_fx):
    # Run 1: a 15 MB 7z declared a 961 MB program. Limits scaled down here: a 400 KB
    # program of zeros over a 50 KB member limit.
    pytest.importorskip("py7zr")
    data = arch_fx.seven_zip({"Setup.exe": b"MZ" + bytes(400_000)})
    r = pipeline.triage(make_file("pumped.7z", data), _pump_options())
    found = ids(r)
    assert found["archive.pumped_member"].value == "high"
    assert r.verdict["value"] in ("suspicious", "malicious")


@pytest.mark.parametrize("name, data", [
    ("big.exe", None),         # over the limit but incompressible: a large real program
    ("disk.dat", bytes(400_000)),  # inflated, but not a program
])
def test_large_members_that_are_not_pumped_programs(make_file, arch_fx, fixtures, name, data):
    pytest.importorskip("py7zr")
    import random
    payload = data if data is not None else random.Random(1).randbytes(400_000)
    r = pipeline.triage(make_file("a.7z", arch_fx.seven_zip({name: payload})), _pump_options())
    assert "archive.pumped_member" not in ids(r)


# Holdout set 2 ---------------------------------------------------------------------

VBS = ("Dim sh\r\nSet sh = CreateObject(\"WScript.Shell\")\r\n"
       "sh.Run \"powershell -nop -w hidden -c calc\", 0\r\n")


@pytest.mark.parametrize("codec", ["utf-16-le", "utf-16-be"])
def test_utf16_script_without_byte_order_mark(make_file, codec):
    # Run 1: an 8.6 MB GuLoader VBScript came back as "Unrecognized binary data" and the
    # script analyzer never ran. Rebuilt here as UTF-16 with no byte-order mark.
    padding = "".join(f"' note {i} lorem ipsum\r\n" for i in range(300))
    r = triage(make_file("a.vbs", (padding + VBS).encode(codec)))
    assert (r.file_type.kind, r.file_type.subtype) == ("script", "vbscript")
    assert "script.vbs.shell" in ids(r) and "script.vbs.powershell" in ids(r)


def test_binary_with_zero_bytes_is_still_binary(make_file):
    import random
    rng = random.Random(7)
    data = bytes(b for _ in range(4000) for b in (rng.randrange(256), 0, 0, rng.randrange(256)))
    r = triage(make_file("blob.dat", data))
    assert r.file_type.kind == "unknown"


def test_js_with_a_huge_payload_line(make_file):
    # Run 1: a RemcosRAT JScript dropper, one line of 3,018,473 characters plus an
    # ActiveXObject call, had a LOW and a MEDIUM and came back "no findings". Rebuilt with a
    # 600,000-character line of letters (no real payload).
    import random
    rng = random.Random(3)
    blob = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(600_000))
    js = (f'var d = "{blob}";\n'
          'var o = new ActiveXObject("Scripting.FileSystemObject");\n')
    r = triage(make_file("PO-1.js", js.encode()))
    found = ids(r)
    assert found["script.long_line"].value == "medium"
    assert found["behavior.com_script_with_payload_line"].value == "high"
    assert r.verdict["value"] in ("suspicious", "malicious")


def test_minified_library_line_stays_low(make_file):
    line = "function a(b){return b+1};" * 4000  # about 100,000 characters, like jQuery
    r = triage(make_file("lib.min.js", (line + "\nvar x = new ActiveXObject('a');\n").encode()))
    assert ids(r)["script.long_line"].value == "low"
    assert "behavior.com_script_with_payload_line" not in ids(r)


class _Node:
    """A member report reduced to what the side-loading check reads."""

    def __init__(self, subtype, sig=None, capa=()):
        from unopened.model import AnalyzerResult, FileType, Status
        self.file_type = FileType("pe", "PE", subtype=subtype)
        self._results = {"capa": AnalyzerResult("capa", Status.OK, data={
            "capabilities": [{"name": c} for c in capa]})}
        if sig is not None:
            self._results["authenticode"] = AnalyzerResult("authenticode", Status.OK, data=sig)

    def result(self, name):
        return self._results.get(name)


def _member(name, node):
    return {"source": "archive", "member": {"name": name}, "report": node}


DROPBOX = {"signed": True, "valid": True,
           "signers": [{"subject": "CN=Dropbox\\, Inc, O=Dropbox\\, Inc, L=San Francisco"}]}
PERSON = {"signed": True, "valid": True,
          "signers": [{"subject": "CN=JANE EXAMPLE, O=JANE EXAMPLE, C=MX"}]}
LOADER = ["allocate or change RWX memory", "contain an embedded PE file",
          "execute shellcode via indirect call", "write file on Windows"]


@pytest.mark.parametrize("dll_sig, why", [
    (PERSON, "signed by someone else"),
    ({"signed": False}, "not signed"),
    ({"signed": True, "valid": False, "signers": []}, "does not verify"),
])
def test_signed_program_with_shellcode_dll_is_side_loading(dll_sig, why):
    # Run 1: an ISO with a Dropbox-signed program and a DLL signed by an individual that
    # allocates RWX memory, embeds a PE and calls shellcode. Each file alone: LOW at most.
    children = [_member("Setup.exe", _Node("exe", DROPBOX)),
                _member("version.dll", _Node("dll", dll_sig, LOADER))]
    found = {f.id: f for f in pipeline.container_findings(children)}
    assert found["container.sideload"].severity.value == "high"
    assert why in found["container.sideload"].detail


@pytest.mark.parametrize("children", [
    # Same publisher signs both.
    [_member("app.exe", _Node("exe", DROPBOX)), _member("lib.dll", _Node("dll", DROPBOX, LOADER))],
    # The DLL has no shellcode call: an ordinary third-party library.
    [_member("app.exe", _Node("exe", DROPBOX)),
     _member("lib.dll", _Node("dll", PERSON, ["allocate or change RWX memory"]))],
    # The program is not validly signed: nothing trusted is being borrowed.
    [_member("app.exe", _Node("exe", {"signed": False})),
     _member("lib.dll", _Node("dll", PERSON, LOADER))],
])
def test_not_side_loading(children):
    assert "container.sideload" not in {f.id for f in pipeline.container_findings(children)}
