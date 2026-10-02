# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Create an external CA request and a leaf signed with its unshared test key."""

from __future__ import annotations

import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def prepare(base: Path) -> None:
    """Model an OpenBao key that stays outside the collection's managed key paths."""
    key = ec.generate_private_key(ec.SECP256R1())
    key_path = base / "external.key"
    key_path.touch(mode=0o600)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenBao CA")])
        )
        .add_extension(x509.BasicConstraints(True, 0), critical=True)
        .sign(key, hashes.SHA256())
    )
    (base / "external.csr").write_bytes(csr.public_bytes(serialization.Encoding.PEM))


def issue_leaf(base: Path) -> None:
    """Use the imported CA certificate and original external key to issue a leaf."""
    issuer = x509.load_pem_x509_certificate(
        (base / "certs/openbao/openbao.pem").read_bytes()
    )
    key = serialization.load_pem_private_key((base / "external.key").read_bytes(), None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "service.example.test")])
        )
        .issuer_name(issuer.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(False, None), critical=True)
        .sign(key, hashes.SHA256())
    )
    (base / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    assert not (base / "certs/openbao/openbao.key").exists()


if __name__ == "__main__":
    {"prepare": prepare, "leaf": issue_leaf}[sys.argv[1]](Path(sys.argv[2]))
