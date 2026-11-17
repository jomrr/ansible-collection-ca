# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""PEM key conversions through the public certificate module."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any
from unittest import TestCase

from ansible_collections.jomrr.ca.plugins.modules import certificate, certificate_batch
from ansible_collections.jomrr.ca.tests.unit.plugins.batch_check_fixture import (
    forbid_mutation,
    snapshot,
)
from ansible_collections.jomrr.ca.tests.unit.plugins.certificate_fixture import (
    CertificateFixture,
)
from ansible_collections.jomrr.ca.tests.unit.plugins.module_fixture import (
    module_diagnostics,
    module_transport,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class PemBundleTests(TestCase):
    """Check export encodings, key identity and FRITZ!Box byte compatibility."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base)
        self.ca = CertificateFixture(self.base)

    def invoke(self, item: dict[str, Any], *, check: bool = False) -> dict[str, Any]:
        """Call the real module including nested options and secret handling."""
        params = self.ca.request()
        params.update(certificate=item, _ansible_check_mode=check)
        run_module = certificate_batch.main if check else certificate.main
        if check:
            params["certificates"] = [params.pop("certificate")]
        with module_transport(params) as (output, log), self.assertRaises(SystemExit):
            run_module()
        self.assertNotIn("bundle-test-secret", module_diagnostics(output, log))
        result: dict[str, Any] = json.loads(output.getvalue())
        if check and "results" in result:
            result = result["results"][0]
        return result

    def predict(self, item: dict[str, Any]) -> dict[str, Any]:
        """Predict changes without modifying keys, exports or inventory."""
        before = snapshot(self.base)
        with forbid_mutation():
            result = self.invoke(item, check=True)
        self.assertEqual(snapshot(self.base), before)
        self.assertNotIn("failed", result, result)
        return result

    def assert_bundle(self, name: str, password: str, header: bytes) -> None:
        """Independently decode the private export and compare its certificate chain."""
        directory = self.base / "certs" / name
        cert = (directory / f"{name}.pem").read_bytes()
        issuer = (self.base / "ca/issuer-ca.pem").read_bytes()
        key = (directory / f"{name}.key").read_bytes()
        path = directory / f"{name}-bundle.pem"
        bundle = path.read_bytes()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertIn(b"-----BEGIN " + header + b"-----", bundle)
        self.assertEqual(
            x509.load_pem_x509_certificates(bundle),
            [x509.load_pem_x509_certificate(part) for part in (cert, issuer)],
        )
        exported = serialization.load_pem_private_key(
            bundle, password.encode() if password else None
        )
        self.assertEqual(
            exported.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            x509.load_pem_x509_certificate(cert)
            .public_key()
            .public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        # This is the previous FRITZ!Box writer's exact concatenation contract.
        self.assertEqual(
            (directory / f"{name}-fritzbox.pem").read_bytes(),
            b"".join(part.rstrip() + b"\n" for part in (cert, issuer, key)),
        )

    def test_encodings_and_format_only_updates(self) -> None:
        """Encryption and encoding changes preserve managed material and FRITZ!Box."""
        for key_type, traditional_header in (
            ("RSA", b"RSA PRIVATE KEY"),
            ("P-256", b"EC PRIVATE KEY"),
        ):
            for password in ("", "bundle-test-secret"):
                with self.subTest(key_type=key_type, encrypted=bool(password)):
                    name = f"web-{key_type}-{bool(password)}"
                    item = {
                        "name": name,
                        "type": "tls_server",
                        "common_name": name,
                        "key_type": key_type,
                        "key_size": 2048,
                        "key_passphrase": password,
                        "formats": ["bundle", "fritzbox"],
                    }
                    self.assertTrue(self.predict(item)["bundle_changed"])
                    updated = self.invoke(item)
                    self.assertNotIn("failed", updated, updated)
                    self.assertTrue(updated["bundle_changed"])
                    directory = self.base / "certs" / name
                    original = {
                        p: p.read_bytes() for p in directory.iterdir() if p.is_file()
                    }
                    pkcs8_header = (
                        b"ENCRYPTED PRIVATE KEY" if password else b"PRIVATE KEY"
                    )
                    for key_format, header, changed in (
                        ("pkcs8", pkcs8_header, False),
                        ("traditional", traditional_header, True),
                        ("pkcs8", pkcs8_header, True),
                    ):
                        item["bundle_key_format"] = key_format
                        self.assertEqual(self.predict(item)["bundle_changed"], changed)
                        updated = self.invoke(item)
                        self.assertNotIn("failed", updated, updated)
                        self.assertFalse(updated["cert_changed"])
                        self.assertFalse(updated["key_changed"])
                        self.assertFalse(updated["fritzbox_bundle_changed"])
                        self.assert_bundle(name, password, header)
                        before_repeat = snapshot(self.base)
                        self.assertFalse(self.predict(item)["changed"])
                        self.assertFalse(self.invoke(item)["changed"])
                        self.assertEqual(snapshot(self.base), before_repeat)
                    self.assertEqual(
                        {path: path.read_bytes() for path in original}, original
                    )

    def test_converted_bundle_repair(self) -> None:
        """Missing, corrupt or foreign keys are repaired without reissuing a leaf."""
        item = {
            "name": "web",
            "type": "tls_server",
            "common_name": "web",
            "key_type": "P-256",
            "key_passphrase": "bundle-test-secret",
            "formats": ["bundle", "fritzbox"],
            "bundle_key_format": "traditional",
        }
        result = self.invoke(item)
        self.assertNotIn("failed", result, result)
        path = Path(result["bundle_path"])
        self.assertNotIn("failed", self.invoke({**item, "name": "other"}))
        foreign = (self.base / "certs/other/other-bundle.pem").read_bytes()
        for content in (None, b"broken PEM", foreign):
            with self.subTest(content=content is None):
                if content is None:
                    path.unlink()
                else:
                    path.write_bytes(content)
                self.assertTrue(self.predict(item)["bundle_changed"])
                updated = self.invoke(item)
                self.assertNotIn("failed", updated, updated)
                self.assertTrue(updated["bundle_changed"])
                self.assertFalse(updated["key_changed"])
                self.assertFalse(updated["cert_changed"])
                self.assert_bundle("web", "bundle-test-secret", b"EC PRIVATE KEY")
                self.assertFalse(self.invoke(item)["changed"])
        path.chmod(0o644)
        self.assertTrue(self.predict(item)["bundle_changed"])
        self.assertTrue(self.invoke(item)["bundle_changed"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_unsupported_keys_and_external_csrs(self) -> None:
        """Reject unavailable key formats before writes; PKCS#8 supports EdDSA."""
        for key_type in ("Ed25519", "Ed448"):
            item = {
                "name": key_type,
                "type": "tls_server",
                "common_name": key_type,
                "key_type": key_type,
                "formats": ["bundle", "fritzbox"],
                "bundle_key_format": "traditional",
            }
            for invalid in ("traditional", "typo"):
                item["bundle_key_format"] = invalid
                before = snapshot(self.base)
                result = self.invoke(item)
                self.assertTrue(result["failed"])
                self.assertEqual(snapshot(self.base), before)
            item["bundle_key_format"] = "pkcs8"
            self.assertNotIn("failed", self.invoke(item))
            self.assert_bundle(key_type, "", b"PRIVATE KEY")
        item = self.ca.request()["certificate"]
        item["formats"] = ["bundle"]
        before = snapshot(self.base)
        result = self.invoke(item)
        self.assertTrue(result["failed"])
        self.assertIn("private key: bundle", result["msg"])
        self.assertEqual(snapshot(self.base), before)
