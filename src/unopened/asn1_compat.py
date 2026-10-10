"""Teach asn1crypto about post-quantum key and signature algorithms.

asn1crypto 1.5.1 maps public-key algorithms to parsers with a fixed table and raises
KeyError for anything else. In M5 validation, Microsoft-signed binaries carried a
certificate with an ML-DSA-87 public key alongside the usual RSA chain; signify touched
every certificate while building its store, hit the KeyError, and gave up on the whole
file, so no signature could be verified.

This registers the FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) identifiers and parses their
keys as opaque bit strings, the same treatment asn1crypto already gives Ed25519 (RFC 8410).
Nothing is verified with these keys: oscrypto cannot, so a chain through one fails
cleanly while the RSA chain beside it is checked as before. The patch only adds entries;
existing algorithms behave exactly as before. It is applied once, by the Authenticode
analyzer, and is a no-op if asn1crypto already knows the algorithms.
"""

from __future__ import annotations

ARC = "2.16.840.1.101.3.4.3"
POST_QUANTUM = {
    f"{ARC}.17": "ml_dsa_44",
    f"{ARC}.18": "ml_dsa_65",
    f"{ARC}.19": "ml_dsa_87",
    **{f"{ARC}.{n}": f"slh_dsa_{n}" for n in range(20, 32)},
}
_applied = False


def apply() -> None:
    global _applied
    if _applied:
        return
    from asn1crypto import algos, core, keys

    for oid, name in POST_QUANTUM.items():
        keys.PublicKeyAlgorithmId._map.setdefault(oid, name)
        algos.SignedDigestAlgorithmId._map.setdefault(oid, name)
    # Keep the reverse maps that asn1crypto builds from _map in step.
    for cls in (keys.PublicKeyAlgorithmId, algos.SignedDigestAlgorithmId):
        if getattr(cls, "_reverse_map", None) is not None:
            cls._reverse_map.update({v: k for k, v in POST_QUANTUM.items()})

    original = keys.PublicKeyInfo._public_key_spec
    names = set(POST_QUANTUM.values())

    def public_key_spec(self):  # type: ignore[no-untyped-def]
        if self["algorithm"]["algorithm"].native in names:
            return (core.OctetBitString, None)
        return original(self)

    keys.PublicKeyInfo._public_key_spec = public_key_spec
    keys.PublicKeyInfo._spec_callbacks = {"public_key": public_key_spec}
    _applied = True
