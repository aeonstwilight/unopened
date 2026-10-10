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
