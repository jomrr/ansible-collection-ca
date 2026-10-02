# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify real certificates using precisely the issuer and CRL from their URLs."""

from __future__ import annotations

import subprocess
import sys
import tarfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def verify(base: Path, name: str, public: dict[str, bytes]) -> tuple[str, str]:
    """Check signature, AKI and OpenSSL revocation independently of module returns."""
    leaf_path = base / f"certs/{name}/{name}.pem"
    leaf = x509.load_pem_x509_certificate(leaf_path.read_bytes())
    aia = (
        leaf.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        .value[0]
        .access_location.value
    )
    cdp_names = (
        leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        .value[0]
        .full_name
    )
    assert cdp_names is not None
    aia_path = str(aia).removeprefix("http://pki.example.test/")
    cdp_path = str(cdp_names[0].value).removeprefix("http://pki.example.test/")
    issuer = x509.load_der_x509_certificate(public[aia_path])
    crl = x509.load_der_x509_crl(public[cdp_path])
    leaf.verify_directly_issued_by(issuer)
    key = issuer.public_key()
    assert isinstance(key, ec.EllipticCurvePublicKey)
    assert crl.is_signature_valid(key)
    assert crl.issuer == issuer.subject
    assert (
        crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        == leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    )
    issuer_path, crl_path = base / "verify-issuer.pem", base / "verify-crl.pem"
    issuer_path.write_bytes(issuer.public_bytes(serialization.Encoding.PEM))
    crl_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    result = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(base / "ca/root-ca.pem"),
            "-untrusted",
            str(issuer_path),
            "-CRLfile",
            str(crl_path),
            "-crl_check",
            str(leaf_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if name == "old":
        assert result.returncode != 0 and "certificate revoked" in result.stderr, (
            result.stderr
        )
    else:
        assert result.returncode == 0, result.stderr
    return aia_path, cdp_path


def main() -> None:
    """Load only the public tar produced by publish_archive and check both issuers."""
    base = Path(sys.argv[1])
    public = {}
    with tarfile.open(base / "public.tar") as archive:
        for member in archive.getmembers():
            assert member.name.startswith(("aia/", "crl/"))
            assert not member.name.endswith(".key")
            stream = archive.extractfile(member)
            assert stream is not None
            public[member.name] = stream.read()
    old_urls = verify(base, "old", public)
    assert old_urls == ("aia/issuer-ca.der", "crl/issuer-ca.crl")
    assert verify(base, "old-valid", public) == old_urls
    new_urls = verify(base, "new", public)
    assert all(old != new for old, new in zip(old_urls, new_urls, strict=True))


if __name__ == "__main__":
    main()
