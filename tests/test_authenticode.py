from __future__ import annotations

import types

import pytest

from unopened import runner
from unopened.analyzers import Context, Options, authenticode, registry
from unopened.identify import identify
from unopened.model import Severity, Status


def analyze(path):
    analyzer = next(a for a in registry() if a.name == "authenticode")
    ctx = Context(path, identify(path), Options(), path.stat().st_size)
    return runner.run_analyzer(analyzer, ctx, isolate=False)


def signify_usable():
    try:
        import signify.authenticode  # noqa: F401
    except Exception:
        return False
    return True


needs_signify = pytest.mark.skipif(not signify_usable(), reason="signify not usable here")


@needs_signify
def test_unsigned(make_file, fixtures):
    r = analyze(make_file("a.exe", fixtures.benign_exe()))
    assert r.status == Status.OK
    assert r.data["signed"] is False and r.data["valid"] is None
    assert r.findings[0].title == "Not digitally signed"
    assert r.findings[0].severity == Severity.INFO


@needs_signify
def test_fake_signature_is_invalid_not_clean(make_file, fixtures):
    r = analyze(make_file("f.exe", fixtures.fake_signed_exe()))
    assert r.status == Status.OK
    assert r.data["signed"] is True and r.data["valid"] is False
    assert r.findings[0].severity in (Severity.MEDIUM, Severity.HIGH)
    assert any("revocation" in n.lower() for n in r.not_checked)


def test_broken_signify_is_unavailable(make_file, fixtures, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("signify"):
            raise OSError("Error detecting the version of libcrypto")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(runner, "_missing_module", lambda names: None)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    r = analyze(make_file("a.exe", fixtures.benign_exe()))
    assert r.status == Status.UNAVAILABLE
    assert "libcrypto" in r.message


@pytest.mark.parametrize(("result_name", "severity", "title"), [
    ("OK", Severity.INFO, "Valid Authenticode signature (signed by CN=Fixture Signer)"),
    ("INVALID_DIGEST", Severity.HIGH, "Signature does not match the file contents"),
    ("CERTIFICATE_ERROR", Severity.MEDIUM, "Signing certificate is not trusted"),
])
def test_verification_outcomes(make_file, fixtures, monkeypatch, result_name, severity, title):
    """Exercise each outcome without a real signed binary by stubbing signify."""
    pytest.importorskip("signify")
    if not signify_usable():
        pytest.skip("signify not usable here")
    from signify.authenticode import AuthenticodeVerificationResult as R

    class FakeFile:
        @staticmethod
        def from_stream(f):
            return FakeFile()

        def explain_verify(self, **kwargs):
            return R[result_name], (None if result_name == "OK" else ValueError("stub"))

        def iter_signatures(self, **kwargs):
            info = types.SimpleNamespace(program_name="Fixture", more_info=None, issuer="CN=CA",
                                         serial_number=1, countersigner=None)
            return [types.SimpleNamespace(signer_info=info, certificates=[], digest_algorithm=None)]

    monkeypatch.setattr(authenticode, "_describe",
                        lambda sig: {"subject": "CN=Fixture Signer", "issuer": "CN=CA"})
    import signify.authenticode as sa

    monkeypatch.setattr(sa, "AuthenticodeFile", FakeFile)
    r = analyze(make_file("a.exe", fixtures.benign_exe()))
    assert r.status == Status.OK
    assert r.findings[0].severity == severity
    assert r.findings[0].title.startswith(title)
    assert r.data["valid"] is (result_name == "OK")


@needs_signify
def test_post_quantum_signature_is_not_evidence(make_file, fixtures, monkeypatch):
    # M5: every Microsoft-signed benign file carried an ML-DSA-87 signature, which signify
    # cannot parse, and was reported as a failed (MEDIUM) signature.
    from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult

    monkeypatch.setattr(
        AuthenticodeFile, "explain_verify",
        lambda self, **kw: (AuthenticodeVerificationResult.UNKNOWN_ERROR,
                            KeyError("2.16.840.1.101.3.4.3.19")))
    r = analyze(make_file("ms.exe", fixtures.fake_signed_exe()))
    assert r.status == Status.PARTIAL  # loud: the check did not complete
    assert r.data["signed"] is True and r.data["unsupported_algorithm"] == "ML-DSA-87"
    (f,) = [f for f in r.findings if f.id.startswith("sig.")]
    assert f.id == "sig.not_verified" and f.severity == Severity.INFO
    assert "ML-DSA-87" in f.detail


@pytest.mark.parametrize("error, algo", [
    (KeyError("2.16.840.1.101.3.4.3.17"), "ML-DSA-44"),
    (ValueError("Signature algorithm not known for 2.16.840.1.101.3.4.3.20"), "SLH-DSA"),
    (ValueError("Insufficient data - 111 bytes requested"), None),
    (None, None),
])
def test_unsupported_algorithm_detection(error, algo):
    assert authenticode.unsupported_algorithm(error) == algo
