# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Create historical and expired PKI fixtures with real certificate signatures."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def rewrite(
    base: Path, name: str, key: ec.EllipticCurvePrivateKey, *, legacy: bool
) -> None:
    """Create a signed fixture and keep its inventory metadata consistent."""
    path = base / f"certs/{name}/{name}.pem"
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    now = datetime.now(UTC)
    before = cert.not_valid_before_utc if legacy else now - timedelta(days=2)
    after = cert.not_valid_after_utc if legacy else now - timedelta(days=1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(cert.issuer)
        .public_key(cert.public_key())
        .serial_number(cert.serial_number)
        .not_valid_before(before)
        .not_valid_after(after)
    )
    for extension in cert.extensions:
        value = extension.value
        if legacy and isinstance(value, x509.AuthorityInformationAccess):
            value = x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        item.access_method,
                        x509.UniformResourceIdentifier(
                            "http://pki.example.test/aia/issuer-ca.der"
                        ),
                    )
                    for item in value
                ]
            )
        elif legacy and isinstance(value, x509.CRLDistributionPoints):
            value = x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(
                                "http://pki.example.test/crl/issuer-ca.crl"
                            )
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            )
        builder = builder.add_extension(value, extension.critical)
    cert = builder.sign(key, hashes.SHA384())
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    record_fixture(base, cert, legacy=legacy)


def record_fixture(base: Path, cert: x509.Certificate, *, legacy: bool) -> None:
    """Update issuance metadata to describe the actual signed test certificate."""
    for record_path in (base / "inventory/state/issued_certificates/issuer").glob(
        "*.json"
    ):
        record = json.loads(record_path.read_text())
        summary = record["certificate"]
        if int(summary["serial_number"]) != cert.serial_number:
            continue
        summary["not_valid_before"] = cert.not_valid_before_utc.isoformat()
        summary["not_valid_after"] = cert.not_valid_after_utc.isoformat()
        for label, digest in (("sha1", hashes.SHA1()), ("sha256", hashes.SHA256())):
            summary["fingerprints"][label] = cert.fingerprint(digest).hex(":").upper()
        if legacy:
            summary["extensions"]["authority_information_access"][0]["location"] = (
                "URI:http://pki.example.test/aia/issuer-ca.der"
            )
            summary["extensions"]["crl_distribution_points"] = [
                ["URI:http://pki.example.test/crl/issuer-ca.crl"]
            ]
        record_path.write_text(json.dumps(record))


def signing_key(path: Path) -> ec.EllipticCurvePrivateKey:
    """Load a synthetic fixture key whose passphrase is not a real credential."""
    key = serialization.load_pem_private_key(path.read_bytes(), b"rollover-test")
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    return key


def main() -> None:
    """Prepare a legacy conflict or retire old certificates and delete their key."""
    base, action = Path(sys.argv[1]), sys.argv[2]
    crl = base / "crl/issuer-ca.crl"
    marker = base / "last-old-crl.sha256"
    if action == "legacy":
        rewrite(base, "new", signing_key(base / "private/issuer-ca.key"), legacy=True)
        shutil.rmtree(base / "generations/issuer")
        for path in (base / "inventory/state/issued_certificates/issuer").glob(
            "*.json"
        ):
            record = json.loads(path.read_text())
            record["certificate"]["extensions"].pop("authority_key_identifier", None)
            path.write_text(json.dumps(record))
    elif action == "expire":
        keys = list(base.glob("archive/authorities/issuer/*/issuer-ca.key"))
        assert len(keys) == 1
        key = signing_key(keys[0])
        for name in ("old", "old-valid"):
            rewrite(base, name, key, legacy=False)
        keys[0].unlink()
        marker.write_text(hashlib.sha256(crl.read_bytes()).hexdigest())
    elif action == "verify-retired":
        assert not list(base.glob("archive/authorities/issuer/*/issuer-ca.key"))
        assert marker.read_text() == hashlib.sha256(crl.read_bytes()).hexdigest()
    else:
        raise ValueError(action)


if __name__ == "__main__":
    main()
