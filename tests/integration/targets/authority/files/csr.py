# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Request unapproved identities and inspect the actual issued certificates."""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID


def untrusted_csr(key: ec.EllipticCurvePrivateKey) -> x509.CertificateSigningRequest:
    """Build the shared regression request with a pinned CN and extra identities."""
    upn = b"administrator@lan.ffebh.de"
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "Max Muster"),
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME, "Andere Organisation"
                    ),
                ]
            )
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.OtherName(
                        x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                        bytes([12, len(upn)]) + upn,
                    ),
                    x509.DNSName("*.lan.ffebh.de"),
                    x509.DNSName("ffebh.de"),
                ]
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def main() -> None:
    """Create a signed hostile CSR or verify task-approved certificate identities."""
    mode, directory = sys.argv[1:]
    base = Path(directory)
    request_path = base / "untrusted.csr"
    if mode == "prepare":
        key = ec.generate_private_key(ec.SECP256R1())
        csr = untrusted_csr(key)
        request_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
        return
    name = "external-batch" if mode == "batch" else "external-max"
    cert = x509.load_pem_x509_certificate(
        (base / f"certs/{name}/{name}.pem").read_bytes()
    )
    csr = x509.load_pem_x509_csr(request_path.read_bytes())
    assert cert.public_key() == csr.public_key()
    assert not (base / f"certs/{name}/{name}.key").exists()
    assert cert.subject == x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Approved Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Max Muster"),
        ]
    )
    issuer = x509.load_pem_x509_certificate((base / "ca/issuer-ca.pem").read_bytes())
    cert.verify_directly_issued_by(issuer)
    assert x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2") in (
        cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    )
    if mode == "approved":
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert not extension.critical
        assert list(extension.value) == [x509.RFC822Name("max@example.test")]
    else:
        assert ExtensionOID.SUBJECT_ALTERNATIVE_NAME not in [
            extension.oid for extension in cert.extensions
        ]


if __name__ == "__main__":
    main()
