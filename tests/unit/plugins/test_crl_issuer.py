# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""CRL issuer identity and repair for CA subjects absent from CRL parameters."""

from __future__ import annotations

import datetime
import unittest
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._crl import (
    build_crl,
    needs_rebuild,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl_models import (
    CrlPlan,
    CrlRequest,
)
from ansible_collections.jomrr.ca.plugins.module_utils._time import now_utc
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class CRLIssuerTests(unittest.TestCase):
    """Use real CA certificates and signed CRLs to exercise issuer comparison."""

    def setUp(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.params: dict[str, Any] = {
            "common_name": "Test CA",
            "subject": {},
            "digest": "sha384",
            "next_update_days": 30,
            "renew_before_days": 7,
            "revoked_certificates": [],
        }

    def plan(self, **overrides: Any) -> CrlPlan:
        """Create the typed plan from ordinary module inputs."""
        return CrlPlan(
            CrlRequest.from_input({**self.params, **overrides}, []), "", "", {}
        )

    def ca_certificate(self, subject: x509.Name) -> x509.Certificate:
        """Sign a CA with the requested subject, including ordered attributes."""
        now = datetime.datetime.now(datetime.UTC)
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(True, 1), critical=True)
            .sign(self.key, hashes.SHA256())
        )

    def test_full_ca_subject_and_legacy_repair(self) -> None:
        """Repair old issuers and preserve email, attribute order and repeated OUs."""
        common_name = x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")
        subjects = (
            x509.Name(
                [
                    common_name,
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, "pki@example.test"),
                ]
            ),
            x509.Name(
                [
                    common_name,
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "First"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Second"),
                ]
            ),
        )
        legacy_ca = self.ca_certificate(x509.Name([common_name]))
        legacy_crl = build_crl(
            self.plan(),
            now=now_utc(strip_microseconds=True),
            crl_number=1,
            ca_cert=legacy_ca,
            private_key=self.key,
        )
        for subject in subjects:
            with self.subTest(subject=subject.rfc4514_string()):
                ca_cert = self.ca_certificate(subject)
                self.assertTrue(
                    needs_rebuild(
                        existing_crls={"pem": legacy_crl, "der": legacy_crl},
                        params=self.plan(),
                        ca_cert=ca_cert,
                        expected_revoked=[],
                    )
                )
                crl = build_crl(
                    self.plan(),
                    now=now_utc(strip_microseconds=True),
                    crl_number=2,
                    ca_cert=ca_cert,
                    private_key=self.key,
                )
                self.assertEqual(
                    crl.issuer.public_bytes(), ca_cert.subject.public_bytes()
                )
                self.assertTrue(crl.is_signature_valid(self.key.public_key()))
                self.assertEqual(
                    crl.extensions.get_extension_for_class(
                        x509.CRLNumber
                    ).value.crl_number,
                    2,
                )
                self.assertFalse(
                    needs_rebuild(
                        existing_crls={"pem": crl, "der": crl},
                        params=self.plan(),
                        ca_cert=ca_cert,
                        expected_revoked=[],
                    )
                )
                self.assertFalse(
                    needs_rebuild(
                        existing_crls={"pem": crl, "der": crl},
                        params=self.plan(
                            common_name="Ignored", subject={"O": "Ignored"}
                        ),
                        ca_cert=ca_cert,
                        expected_revoked=[],
                    )
                )
