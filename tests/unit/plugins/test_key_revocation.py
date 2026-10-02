# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Do not certify keys known to have been compromised through renewal or a CSR."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_engine import (
    ensure_certificate_artifacts,
    ensure_certificate_batch,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl import _build_crl
from ansible_collections.jomrr.ca.plugins.module_utils._inventory import (
    resolve_revocation_entries,
    update_crl_inventory,
)
from ansible_collections.jomrr.ca.tests.unit.plugins.certificate_fixture import (
    CertificateFixture,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class KeyRevocationTests(unittest.TestCase):
    """Exercise the real issuance engine, persistent history and CRL inventory."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base)
        self.ca = CertificateFixture(self.base)
        self.params = self.ca.request()
        self.params["certificate"] = {
            "name": "web",
            "common_name": "web.example.test",
            "type": "tls_server",
            "key_type": "P-256",
            "formats": ["pem"],
            "days": 1,
        }
        result = ensure_certificate_artifacts(self.params)
        self.path = Path(result["cert_path"])
        self.original = x509.load_pem_x509_certificate(self.path.read_bytes())
        private_key = serialization.load_pem_private_key(
            self.path.with_suffix(".key").read_bytes(), None
        )
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        self.key = private_key

    def revoke(self, reason: str = "key_compromise", selector: str = "name") -> None:
        """Record a real CRL revocation using a supported selector."""
        value = {
            "name": "web",
            "serial": self.original.serial_number,
            "sha256": self.original.fingerprint(hashes.SHA256()).hex(),
        }[selector]
        params = {
            **self.params,
            "name": "issuer",
            "digest": "sha384",
            "next_update_days": 30,
            "paths": {"pem": str(self.base / "revoked.crl.pem")},
        }
        params["revoked_certificates"] = resolve_revocation_entries(
            base_dir=str(self.base),
            authority="issuer",
            entries=[{selector: value, "reason": reason}],
        )
        issuer = x509.load_pem_x509_certificate(
            (self.base / "ca/issuer-ca.pem").read_bytes()
        )
        key = serialization.load_pem_private_key(
            (self.base / "private/issuer-ca.key").read_bytes(), b"test-passphrase"
        )
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        crl = _build_crl(params, crl_number=1, ca_cert=issuer, private_key=key)
        update_crl_inventory(params, crl)

    def test_renewal_requires_new_key(self) -> None:
        """Default renewal fails without overwriting the compromised generation."""
        self.revoke()
        paths = [self.path, self.path.with_suffix(".key"), self.base / "csr/web.csr"]
        before = [path.read_bytes() for path in paths]
        with self.assertRaisesRegex(ValueError, "public key recorded as compromised"):
            ensure_certificate_artifacts(self.params)
        self.assertEqual(before, [path.read_bytes() for path in paths])
        self.params["certificate"].update(days=90, renewal={"rekey": True})
        result = ensure_certificate_artifacts(self.params)
        current = x509.load_pem_x509_certificate(self.path.read_bytes())
        self.assertTrue(result["key_changed"])
        self.assertNotEqual(current.public_key(), self.original.public_key())
        self.assertNotEqual(current.serial_number, self.original.serial_number)
        self.assertFalse(ensure_certificate_artifacts(self.params)["changed"])

    def test_serial_revocation_blocks_batch_and_profile_changes(self) -> None:
        """A SAN update cannot bypass revocation, even outside the renewal window."""
        self.revoke(selector="serial")
        self.params["certificate"].update(
            renewal={"renew_before_days": 0}, san=["DNS:updated.example.test"]
        )
        self.params["certificates"] = [self.params.pop("certificate")]
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "public key recorded as compromised"):
            ensure_certificate_batch(self.params)
        self.assertEqual(self.path.read_bytes(), before)

    def test_external_csr_cannot_reuse_compromised_key_after_rekey(self) -> None:
        """Fingerprint revocations survive a new generation and a renamed CSR."""
        self.revoke(selector="sha256")
        self.params["force"] = True
        self.params["certificate"]["days"] = 90
        ensure_certificate_artifacts(self.params)
        for key, rejected in (
            (self.key, True),
            (ec.generate_private_key(ec.SECP256R1()), False),
        ):
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(self.original.subject)
                .sign(key, hashes.SHA256())
            )
            self.params["certificate"].update(
                name="renamed",
                csr_content=csr.public_bytes(serialization.Encoding.PEM).decode(),
            )
            if rejected:
                with self.assertRaisesRegex(
                    ValueError, "public key recorded as compromised"
                ):
                    ensure_certificate_artifacts(self.params)
                self.assertFalse((self.base / "csr/renamed.csr").exists())
                self.assertFalse((self.base / "certs/renamed").exists())
            else:
                self.assertTrue(
                    ensure_certificate_artifacts(self.params)["cert_changed"]
                )

    def test_legacy_inventory_uses_archived_certificate(self) -> None:
        """Older records without a key hash still block the original archived key."""
        self.revoke()
        record_path = next(
            (self.base / "inventory/state/issued_certificates/issuer").glob("*.json")
        )
        record: dict[str, Any] = json.loads(record_path.read_text())
        record["certificate"].pop("public_key_sha256")
        record_path.write_text(json.dumps(record))
        self.params["force"] = True
        ensure_certificate_artifacts(self.params)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(self.original.subject)
            .sign(self.key, hashes.SHA256())
        )
        self.params["certificate"].update(
            csr_content=csr.public_bytes(serialization.Encoding.PEM).decode()
        )
        with self.assertRaisesRegex(ValueError, "public key recorded as compromised"):
            ensure_certificate_artifacts(self.params)
        archive = (
            self.base
            / "archive/certificates/web"
            / record["certificate"]["serial_number_hex"]
            / "web.pem"
        )
        archive.unlink()
        with self.assertRaisesRegex(ValueError, "restore its recorded certificate"):
            ensure_certificate_artifacts(self.params)

    def test_ca_compromise_and_superseded_are_distinct(self) -> None:
        """CA compromise also rejects reuse; supersession alone does not taint a key."""
        self.revoke(reason="ca_compromise")
        with self.assertRaisesRegex(ValueError, "public key recorded as compromised"):
            ensure_certificate_artifacts(self.params)
        self.revoke(reason="superseded")
        result = ensure_certificate_artifacts(self.params)
        current = x509.load_pem_x509_certificate(self.path.read_bytes())
        self.assertTrue(result["cert_changed"])
        self.assertEqual(current.public_key(), self.original.public_key())
