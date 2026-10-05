# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""MSKDC issuance with optional objectGUID and required PKINIT configuration."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_engine import (
    ensure_certificate_artifacts,
)
from ansible_collections.jomrr.ca.tests.unit.plugins.certificate_fixture import (
    CertificateFixture,
)
from cryptography import x509


class MskdcTests(unittest.TestCase):
    """Inspect real issued certificates and reject invalid inputs before writes."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base)
        self.params = CertificateFixture(self.base).request()
        self.params["certificate_types"] = {"mskdc": {"issuer": "issuer"}}
        self.params["certificate"] = {
            "name": "dc",
            "type": "mskdc",
            "common_name": "dc.example.test",
            "krb5_realm": "EXAMPLE.TEST",
            "key_type": "P-256",
            "formats": ["pem"],
        }

    def test_optional_guid_extension_and_updates(self) -> None:
        """Add and remove the optional extension without changing PKINIT defaults."""
        guid = "8f2a02d1-862a-47cf-9a9b-6bda9c3bd2c5"
        raw_guid = "d1022a8f2a86cf479a9b6bda9c3bd2c5"
        oid = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.1")
        cases: tuple[tuple[dict[str, Any], bool], ...] = (
            ({}, True),
            ({"ad_object_guid": guid}, True),
            ({"ad_object_guid": raw_guid}, False),
            ({"ad_object_guid": ""}, True),
            ({"ad_object_guid": None}, False),
            ({"ad_object_guid": "  "}, False),
        )
        for override, changed in cases:
            with self.subTest(override=override):
                params = {
                    **self.params,
                    "certificate": {**self.params["certificate"], **override},
                }
                result = ensure_certificate_artifacts(params)
                self.assertEqual(result["cert_changed"], changed)
                self.assertFalse(ensure_certificate_artifacts(params)["changed"])
                cert = x509.load_pem_x509_certificate(
                    Path(result["cert_path"]).read_bytes()
                )
                if override.get("ad_object_guid") in (guid, raw_guid):
                    self.assertEqual(
                        cert.extensions.get_extension_for_oid(oid).value,
                        x509.UnrecognizedExtension(
                            oid, bytes.fromhex("0410" + raw_guid)
                        ),
                    )
                else:
                    with self.assertRaises(x509.ExtensionNotFound):
                        cert.extensions.get_extension_for_oid(oid)
                san = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
                self.assertEqual(
                    san.get_values_for_type(x509.DNSName), ["dc.example.test"]
                )
                self.assertEqual(
                    [name.type_id for name in san.get_values_for_type(x509.OtherName)],
                    [x509.ObjectIdentifier("1.3.6.1.5.2.2")],
                )
                cert.extensions.get_extension_for_oid(
                    x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2")
                )

    def test_invalid_mskdc_inputs_fail_before_writes(self) -> None:
        """Making the GUID optional does not accept malformed GUIDs or realms."""
        for field, value in (
            ("ad_object_guid", "invalid-guid"),
            ("ad_object_guid", "1234"),
            ("krb5_realm", ""),
        ):
            with self.subTest(field=field, value=value):
                self.params["certificate"][field] = value
                with self.assertRaisesRegex(ValueError, field):
                    ensure_certificate_artifacts(self.params)
                del self.params["certificate"][field]
                self.assertFalse((self.base / "certs/dc").exists())
                self.assertFalse((self.base / "csr/dc.csr").exists())
