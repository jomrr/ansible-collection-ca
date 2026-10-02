# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Inspect the revoked generation and generate an external CSR using its key."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def material_hashes(base: Path) -> dict[str, str]:
    """Fingerprint outputs so rejected requests cannot silently replace them."""
    return {
        name: hashlib.sha256((base / name).read_bytes()).hexdigest()
        for name in ("certs/web/web.pem", "certs/web/web.key", "csr/web.csr")
    }


def main() -> None:
    """Prepare or inspect a real revoked-key renewal scenario."""
    mode, directory = sys.argv[1:]
    base = Path(directory)
    current = x509.load_pem_x509_certificate((base / "certs/web/web.pem").read_bytes())
    original_path = base / "original.pem"
    if mode == "prepare":
        original_path.write_bytes(current.public_bytes(serialization.Encoding.PEM))
        (base / "material-hashes.json").write_text(json.dumps(material_hashes(base)))
        key = serialization.load_pem_private_key(
            (base / "certs/web/web.key").read_bytes(), None
        )
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(current.subject)
            .sign(key, hashes.SHA256())
        )
        (base / "compromised.csr").write_bytes(
            csr.public_bytes(serialization.Encoding.PEM)
        )
        return
    if mode == "unchanged":
        assert material_hashes(base) == json.loads(
            (base / "material-hashes.json").read_text()
        )
        assert not (base / "certs/reused-key").exists()
        assert not (base / "csr/reused-key.csr").exists()
        return
    original = x509.load_pem_x509_certificate(original_path.read_bytes())
    assert current.public_key() != original.public_key()
    assert current.serial_number != original.serial_number
    crl = x509.load_pem_x509_crl((base / "crl/issuer-ca.crl.pem").read_bytes())
    assert (
        crl.get_revoked_certificate_by_serial_number(original.serial_number) is not None
    )
    assert crl.get_revoked_certificate_by_serial_number(current.serial_number) is None
    key = serialization.load_pem_private_key(
        (base / "certs/web/web.key").read_bytes(), None
    )
    assert key.public_key() == current.public_key()


if __name__ == "__main__":
    main()
