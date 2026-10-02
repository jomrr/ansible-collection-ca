# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Select managed CA and leaf certificates without crossing issuer boundaries."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._inventory import (
    resolve_revocation_entries,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    load_certificate,
)
from ansible_collections.jomrr.ca.tests.unit.plugins.certificate_fixture import (
    CertificateFixture,
)
from cryptography.hazmat.primitives import hashes


class RevocationSelectorTests(unittest.TestCase):
    """Exercise selectors against real current and historical inventory records."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base)
        self.ca = CertificateFixture(self.base)
        self.original = load_certificate(str(self.base / "ca/issuer-ca.pem"))

    def resolve(self, authority: str = "root", **entry: Any) -> dict[str, Any]:
        """Resolve one declaration without persisting a CRL."""
        return resolve_revocation_entries(
            base_dir=str(self.base), authority=authority, entries=[entry]
        )[0]

    def test_authority_name_and_fingerprint_aliases(self) -> None:
        """All existing selectors also identify managed CA certificates."""
        sha1 = self.original.fingerprint(hashes.SHA1()).hex(":").upper()
        sha256 = self.original.fingerprint(hashes.SHA256()).hex(":").upper()
        selectors = [
            {alias: "issuer"} for alias in ("name", "certificate", "certificate_name")
        ] + [
            {"sha1": sha1},
            {"sha256": sha256},
            {"fingerprint": sha256},
            {"fingerprint": f"sha256:{sha256}"},
            {"fingerprint": f"SHA-1:{sha1}"},
        ]
        for selector in selectors:
            with self.subTest(selector=selector):
                record = self.resolve(**selector, reason="ca_compromise")
                self.assertEqual(
                    record["serial_number"], str(self.original.serial_number)
                )
                self.assertEqual(record["issuer"], "root")
                self.assertEqual(record["certificate_name"], "issuer")
                self.assertEqual(record["fingerprints"]["sha256"], sha256)
                self.assertEqual(record["reason"], "ca_compromise")

    def test_fingerprint_selects_archived_ca_while_name_selects_current(self) -> None:
        """A CA rollover retains the exact older certificate fingerprint lookup."""
        result = self.ca.authority("issuer", "root", force=True)
        current = load_certificate(result["cert_path"])
        self.assertNotEqual(current.serial_number, self.original.serial_number)
        old_record = self.resolve(
            sha256=self.original.fingerprint(hashes.SHA256()).hex()
        )
        self.assertEqual(old_record["serial_number"], str(self.original.serial_number))
        self.assertEqual(
            self.resolve(name="issuer")["serial_number"], str(current.serial_number)
        )

    def test_wrong_issuer_and_unknown_selectors_are_rejected(self) -> None:
        """A CA can only be selected for its actual parent's CRL."""
        with self.assertRaisesRegex(ValueError, "issued by root, not issuer"):
            self.resolve("issuer", name="issuer")
        with self.assertRaisesRegex(ValueError, "No issued certificate"):
            self.resolve(
                "issuer", sha256=self.original.fingerprint(hashes.SHA256()).hex()
            )
        with self.assertRaisesRegex(ValueError, "No current certificate"):
            self.resolve(name="missing")
        with self.assertRaisesRegex(ValueError, "No issued certificate"):
            self.resolve(sha256="00" * 32)

    def test_same_name_under_different_issuers_is_unambiguous(self) -> None:
        """Only candidates issued by the CRL authority participate in selection."""
        leaf = self.ca.leaf("issuer")
        self.assertEqual(
            self.resolve(name="issuer")["serial_number"],
            str(self.original.serial_number),
        )
        self.assertEqual(
            self.resolve("issuer", name="issuer")["serial_number"],
            str(leaf.serial_number),
        )

    def test_same_name_under_same_issuer_requires_exact_selector(self) -> None:
        """Never silently revoke the wrong object when CA and leaf names collide."""
        leaf = self.ca.leaf("issuer", issuer="root")
        with self.assertRaisesRegex(ValueError, "multiple.*fingerprint or serial"):
            self.resolve(name="issuer")
        for cert in (leaf, self.original):
            with self.subTest(serial=cert.serial_number):
                record = self.resolve(sha256=cert.fingerprint(hashes.SHA256()).hex())
                self.assertEqual(record["serial_number"], str(cert.serial_number))
