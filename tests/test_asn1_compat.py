"""Post-quantum certificates must not stop signature verification (M5 validation).

Microsoft-signed binaries in the benign corpus carried a certificate with an ML-DSA-87
public key. signify hashed every certificate while building its store, asn1crypto raised
KeyError('2.16.840.1.101.3.4.3.19'), and the whole file came back unverifiable.
The certificate here is synthetic: a bundled legacy root with its key swapped for an
ML-DSA one.
"""

from __future__ import annotations

import os
import sys

import pytest

signify = pytest.importorskip("signify")
pytest.importorskip("signify.x509")

from asn1crypto import core, keys, pem, x509  # noqa: E402

from unopened import asn1_compat  # noqa: E402

ML_DSA_87 = "2.16.840.1.101.3.4.3.19"


def base_der() -> bytes:
    path = os.path.join(os.path.dirname(signify.__file__), "authenticode", "legacy-certs.pem")
    with open(path, "rb") as f:
        return next(pem.unarmor(f.read(), multiple=True))[2]


def mldsa_der() -> bytes:
    """DER for a certificate with an ML-DSA-87 key, assembled without going through
    PublicKeyInfo's algorithm table, so it can be built before the patch is applied."""
    original = x509.Certificate.load(base_der())
    tbs = x509.TbsCertificate.load(original["tbs_certificate"].dump())
    spki = core.Sequence(contents=(
        core.Sequence(contents=core.ObjectIdentifier(ML_DSA_87).dump()).dump()
        + core.BitString((0,) * 512).dump()
    ))
    body = b"".join(spki.dump() if name == "subject_public_key_info" else tbs[name].dump()
                    for name, *_ in x509.TbsCertificate._fields)
    return core.Sequence(contents=core.Sequence(contents=body).dump()
                         + original["signature_algorithm"].dump()
                         + original["signature_value"].dump()).dump()


def test_reproduces_the_crash_and_the_fix():
    from signify.x509 import Certificate

    der = mldsa_der()
    if not asn1_compat._applied:
        # Without the patch: the exact failure seen in the VM.
        cert = Certificate(x509.Certificate.load(der))
        with pytest.raises(KeyError, match=ML_DSA_87):
            hash(cert)
    asn1_compat.apply()
    cert = Certificate(x509.Certificate.load(der))
    assert hash(cert)
    assert cert.subject_public_algorithm.algorithm == "ml_dsa_87"


def test_apply_is_idempotent_and_keeps_known_algorithms():
    asn1_compat.apply()
    asn1_compat.apply()
    rsa = x509.Certificate.load(base_der())
    assert rsa["tbs_certificate"]["subject_public_key_info"]["algorithm"]["algorithm"].native \
        == "rsa"
    assert isinstance(rsa.public_key["public_key"].parsed, keys.RSAPublicKey)


def test_authenticode_analyzer_applies_it():
    src = os.path.join(os.path.dirname(asn1_compat.__file__), "analyzers", "authenticode.py")
    with open(src, encoding="utf-8") as f:
        assert "asn1_compat.apply()" in f.read()
    assert sys.modules.get("unopened.asn1_compat") is not None
