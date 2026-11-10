# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""All three batch modules predict real changes without mutating CA state."""

from __future__ import annotations

import copy
import json
import os
import shutil
from datetime import timedelta
from pathlib import Path
from tempfile import mkdtemp
from typing import Any
from unittest import TestCase
from unittest.mock import patch

from ansible_collections.jomrr.ca.plugins.module_utils._time import now_utc
from ansible_collections.jomrr.ca.plugins.modules import (
    authority_batch,
    certificate_batch,
    crl_batch,
)
from ansible_collections.jomrr.ca.tests.unit.plugins.batch_check_fixture import (
    forbid_mutation,
    snapshot,
)
from ansible_collections.jomrr.ca.tests.unit.plugins.module_fixture import (
    module_diagnostics,
    module_transport,
)

MODULES = {
    "authority": authority_batch,
    "certificate": certificate_batch,
    "crl": crl_batch,
}


class BatchCheckModeTests(TestCase):
    """Use Ansible's actual argument and result handling for the check-mode path."""

    def setUp(self) -> None:
        self.root = Path(mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.base = self.root / "pki"
        self.params: dict[str, Any] = {
            "base_dir": str(self.base),
            "ca_name": "check",
            "base_url": "https://pki.example.test",
            "owner": str(os.getuid()),
            "group": str(os.getgid()),
            "authorities": [
                {
                    "name": name,
                    "parent": "root",
                    "common_name": name,
                    "days": 365,
                    "key_type": "P-256",
                    "key_passphrase": "check-test-secret",
                    "crl_days": 30,
                    "default_days": 90,
                }
                for name in ("issuer", "root")
            ],
        }
        self.leaf = {
            "name": "web",
            "common_name": "web.example.test",
            "type": "tls_server",
            "key_type": "P-256",
            "key_passphrase": "check-leaf-secret",
            "pfx_passphrase": "check-pfx-secret",
            "formats": ["pem", "der", "txt", "pfx", "p12", "fullchain", "fritzbox"],
        }

    def invoke(
        self, name: str, *, check: bool = False, **overrides: Any
    ) -> dict[str, Any]:
        """Exercise the public module, and inspect redacted diagnostics and results."""
        inputs = copy.deepcopy(self.params)
        if name == "certificate":
            inputs.update(
                certificate_types={"tls_server": {"issuer": "issuer"}},
                certificates=[self.leaf],
            )
        inputs.update(overrides, _ansible_check_mode=check)
        with module_transport(inputs) as (output, log), self.assertRaises(SystemExit):
            MODULES[name].main()
        emitted = module_diagnostics(output, log)
        for secret in ("check-test-secret", "check-leaf-secret", "check-pfx-secret"):
            self.assertNotIn(secret, emitted)
        result: dict[str, Any] = json.loads(output.getvalue())
        return result

    def predict(self, name: str, **overrides: Any) -> dict[str, Any]:
        """Assert no writes or metadata changes even for failure predictions."""
        before = snapshot(self.root)
        with forbid_mutation():
            result = self.invoke(name, check=True, **overrides)
        self.assertEqual(before, snapshot(self.root))
        return result

    def converge(self) -> None:
        """Create actual CA, certificate and CRL state through the three modules."""
        for name in MODULES:
            result = self.invoke(name)
            self.assertNotIn("failed", result, result)

    def test_missing_converged_force_and_empty(self) -> None:
        """Predict first creation, no-op and force without creating even lock files."""
        for name in MODULES:
            with self.subTest(name=name):
                result = self.predict(name)
                self.assertNotIn("failed", result, result)
                self.assertTrue(result["changed"])
                self.assertFalse(self.base.exists())
                empty: dict[str, Any] = (
                    {"certificates": []}
                    if name == "certificate"
                    else {"authorities": []}
                )
                self.assertFalse(self.predict(name, **empty)["changed"])
        self.converge()
        for name in MODULES:
            with self.subTest(name=name):
                result = self.predict(name)
                self.assertNotIn("failed", result, result)
                self.assertFalse(result["changed"], result)
                self.assertTrue(self.predict(name, force=True)["changed"])
                self.assertFalse(self.invoke(name)["changed"])

    def test_file_repairs_and_revocations(self) -> None:
        """Detect missing exports, changed bytes, file modes and new revocations."""
        self.converge()
        paths = {
            "authority": self.base / "ca/issuer-ca.der",
            "certificate": self.base / "certs/web/web.der",
            "crl": self.base / "crl/issuer-ca.crl",
        }
        for name, path in paths.items():
            with self.subTest(name=name):
                self.assertTrue(path.exists(), path)
                for damage in ("mode", "content", "missing"):
                    if damage == "mode":
                        path.chmod(0o600)
                    elif damage == "content":
                        path.write_bytes(b"damaged")
                    else:
                        path.unlink()
                    result = self.predict(name)
                    self.assertNotIn("failed", result, result)
                    self.assertTrue(result["changed"], result)
                    self.assertTrue(self.invoke(name)["changed"])
                    self.assertFalse(self.predict(name)["changed"])
        revoked = {"issuer": [{"name": "web", "reason": "superseded"}]}
        result = self.predict("crl", revocations=revoked)
        self.assertEqual([item["changed"] for item in result["results"]], [True, False])
        self.assertEqual(
            result["results"][0]["crl_number"],
            self.invoke("crl", revocations=revoked)["results"][0]["crl_number"],
        )

    def test_renewal_and_parent_dependencies(self) -> None:
        """Renewal preserves keys unless requested; descendant chains still change."""
        self.converge()
        for name in ("authority", "certificate"):
            result = self.predict(name, renewal={"renew_before_days": 400})
            self.assertNotIn("failed", result, result)
            self.assertTrue(result["changed"])
        future = now_utc() + timedelta(days=24)
        with patch(
            "ansible_collections.jomrr.ca.plugins.module_utils._crl.now_utc",
            return_value=future,
        ):
            self.assertTrue(self.predict("crl")["changed"])
        authorities = copy.deepcopy(self.params["authorities"])
        authorities[1]["renewal"] = {"renew_before_days": 400}
        predicted = self.predict("authority", authorities=authorities)
        actual = self.invoke("authority", authorities=authorities)
        self.assertEqual(
            [item["changed"] for item in predicted["results"]],
            [item["changed"] for item in actual["results"]],
        )

    def test_invalid_configuration_without_material(self) -> None:
        """Reject invalid subjects and extensions before a key exists in check mode."""
        for index, override in enumerate(
            (
                {"common_name": ""},
                {"subject": {"country": "DEU"}},
                {"san": ["IP:invalid"]},
                {"raw_extensions": [{"oid": "1.2.3", "value": "unsupported"}]},
            )
        ):
            authorities = copy.deepcopy(self.params["authorities"])
            authorities[1].update(override)
            with self.subTest(override=override):
                values = {
                    "authorities": authorities,
                    "base_dir": str(self.root / f"invalid-{index}"),
                }
                self.assertTrue(self.predict("authority", **values)["failed"])
                self.assertTrue(self.invoke("authority", **values)["failed"])

    def test_credentials_missing_keys_and_symlinks(self) -> None:
        """Operational failures remain errors and never repair state in check mode."""
        self.converge()
        authorities = copy.deepcopy(self.params["authorities"])
        authorities[0]["key_passphrase"] = "wrong-check-secret"
        for name in MODULES:
            self.assertTrue(self.predict(name, authorities=authorities)["failed"])
        key = self.base / "private/issuer-ca.key"
        key.unlink()
        self.assertTrue(self.predict("authority")["changed"])
        self.assertTrue(self.predict("certificate")["failed"])
        self.assertTrue(self.predict("crl")["failed"])
        self.invoke("authority")
        target = self.base / "ca/issuer-ca.der"
        target.unlink()
        target.symlink_to(self.base / "ca/root-ca.der")
        self.assertTrue(self.predict("authority")["failed"])
        self.assertTrue(self.predict("authority", force=True)["failed"])
