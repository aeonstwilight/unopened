"""Authenticode signature presence and validity, using signify.

Verification is offline: the certificate chain is checked against the Microsoft
trusted-root list bundled with signify. Revocation (CRL/OCSP) needs the network and is
never checked; the report lists it under "Not checked".
"""

from __future__ import annotations

from typing import Any

from ..model import AnalyzerOutput, Finding, Severity
from . import AnalyzerUnavailable, Context

SIGNED_MALWARE_NOTE = (
    "A valid signature tells you who signed the file, not that it is safe: malware is "
    "sometimes signed with stolen or fraudulently obtained certificates."
)

FAILURES: dict[str, tuple[Severity, str, str]] = {
    "INVALID_DIGEST": (
        Severity.HIGH, "Signature does not match the file contents",
        "The file was changed after it was signed, or the signature was copied from another "
        "file to borrow its credibility.",
    ),
    "PARSE_ERROR": (
        Severity.MEDIUM, "Signature data is present but malformed",
        "The file carries signature data that cannot be parsed: damaged, or a fake signature "
        "meant to look signed at a glance.",
    ),
    "CERTIFICATE_ERROR": (
        Severity.MEDIUM, "Signing certificate is not trusted",
        "The certificate does not chain to a trusted root or is not valid for code signing "
        "(for example self-signed, untrusted issuer, or expired without a timestamp).",
    ),
}
GENERIC_FAILURE = (
    Severity.MEDIUM, "Signature failed verification",
    "The file carries a signature that does not verify.",
)
# Post-quantum signature algorithms (FIPS 204 ML-DSA, FIPS 205 SLH-DSA) that signify does
# not know yet. In M5 validation every Microsoft-signed file in the benign corpus carried an
# ML-DSA-87 signature (OID ...3.4.3.19) and the verifier stopped on it. That says nothing
# about the file, so it is reported loudly as an incomplete check, never as evidence. Any
# other verifier error (for example malformed signature data) stays a MEDIUM finding.
UNSUPPORTED_ALGORITHMS = {
    f"2.16.840.1.101.3.4.3.{n}": name
    for n, name in [(17, "ML-DSA-44"), (18, "ML-DSA-65"), (19, "ML-DSA-87")]
    + [(n, "SLH-DSA") for n in range(20, 32)]
}


def unsupported_algorithm(error: BaseException | None) -> str | None:
    text = f"{error!r} {error}" if error else ""
    return next((name for oid, name in UNSUPPORTED_ALGORITHMS.items() if oid in text), None)


def analyze_authenticode(ctx: Context) -> AnalyzerOutput:
    try:
        from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult
    except Exception as exc:  # e.g. oscrypto cannot find or recognize libcrypto
        raise AnalyzerUnavailable(
            f"signify is installed but could not be loaded ({type(exc).__name__}: {exc})"
        ) from exc

    out = AnalyzerOutput()
    with ctx.path.open("rb") as f:
        signed_file = AuthenticodeFile.from_stream(f)
        result, error = signed_file.explain_verify(signature_types="embedded")
        signers: list[dict[str, Any]] = []
        if result != AuthenticodeVerificationResult.NOT_SIGNED:
            try:
                for sig in signed_file.iter_signatures(signature_types="embedded"):
                    signers.append(_describe(sig))
            except Exception as exc:
                problem = f"{type(exc).__name__}: {exc}"
                if result == AuthenticodeVerificationResult.OK:
                    out.errors.append(f"reading signer details: {problem}")
                else:  # same root cause as the failed verification, already reported
                    out.data["signer_details_error"] = problem

    signed = result != AuthenticodeVerificationResult.NOT_SIGNED
    valid = result == AuthenticodeVerificationResult.OK
    out.data |= {
        "signed": signed,
        "valid": valid if signed else None,
        "result": result.name,
        "detail": f"{type(error).__name__}: {error}" if error and signed else None,
        "signers": signers,
        "trust_store": "Microsoft trusted root list bundled with signify",
        "revocation_checked": False,
    }
    if not signed:
        out.findings.append(Finding(
            "sig.unsigned",
            Severity.INFO, "Not digitally signed",
            "Most malware is unsigned, but so is plenty of legitimate software; on its own "
            "this means little.",
        ))
        return out
    out.not_checked.append("Certificate revocation (CRL/OCSP needs network access)")
    who = _signer_summary(signers)
    if valid:
        out.findings.append(Finding(
            "sig.valid",
            Severity.INFO, f"Valid Authenticode signature{who}", SIGNED_MALWARE_NOTE
        ))
    elif result.name == "UNKNOWN_ERROR" and (algo := unsupported_algorithm(error)):
        out.data["unsupported_algorithm"] = algo
        out.errors.append(f"signature uses {algo}, which the verifier does not support yet; "
                          "validity was not checked")
        out.findings.append(Finding(
            "sig.not_verified", Severity.INFO, "Signature present, could not be verified" + who,
            f"The file carries a {algo} (post-quantum) signature that the verifier does not "
            "support yet, so the signatures were neither confirmed nor refuted. This says "
            "nothing about the file either way.",
        ))
    else:
        severity, title, detail = FAILURES.get(result.name, GENERIC_FAILURE)
        reason = f" Verifier said: {out.data['detail']}" if out.data["detail"] else ""
        out.findings.append(
            Finding(f"sig.{result.name.lower()}", severity, title + who, detail + reason)
        )
    return out


def _signer_summary(signers: list[dict[str, Any]]) -> str:
    subjects = [s["subject"] for s in signers if s.get("subject")]
    return f" (signed by {subjects[0]})" if subjects else ""


def _describe(sig: Any) -> dict[str, Any]:
    info = sig.signer_info
    desc: dict[str, Any] = {
        "program_name": getattr(info, "program_name", None),
        "more_info": getattr(info, "more_info", None),
        "digest_algorithm": getattr(getattr(sig, "digest_algorithm", None), "__name__", None),
        "issuer": _dn(getattr(info, "issuer", None)),
        "serial_number": str(getattr(info, "serial_number", "")) or None,
    }
    for cert in getattr(sig, "certificates", []) or []:
        if cert.serial_number == info.serial_number and cert.issuer == info.issuer:
            desc["subject"] = _dn(cert.subject)
            desc["valid_from"] = cert.valid_from.isoformat()
            desc["valid_to"] = cert.valid_to.isoformat()
            desc["sha256_fingerprint"] = cert.sha256_fingerprint
            break
    counter = getattr(info, "countersigner", None)
    signing_time = getattr(counter, "signing_time", None) if counter else None
    desc["timestamp"] = signing_time.isoformat() if signing_time else None
    return desc


def _dn(name: Any) -> str | None:
    if name is None:
        return None
    return getattr(name, "dn", None) or str(name)
