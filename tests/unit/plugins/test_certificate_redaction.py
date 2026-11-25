# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Certificate results remain usable while Ansible masks only secret values."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from ansible.module_utils.common.parameters import PASS_VARS
from ansible_collections.jomrr.ca.plugins.modules import (
    certificate,
    certificate_batch,
    publish,
    publish_archive,
)
from ansible_collections.jomrr.ca.tests.unit.plugins.module_fixture import (
    module_diagnostics,
    module_transport,
)


class CertificateRedactionTests(unittest.TestCase):
    """Exercise real Ansible argument loading, validation, logging and JSON output."""

    def setUp(self) -> None:
        self.secrets = [
            "issuer-test-secret",
            "parent-test-secret",
            "export-test-secret",
            "alias-test-secret",
            "xy",
            "archived-test-secret",
            "deployment-test-secret",
        ]
        self.inputs: dict[str, Any] = {
            "base_dir": "/tmp/pki",
            "certificate_types": {"tls_server": {"issuer": "issuer"}},
            "authorities": [
                {
                    "name": "issuer",
                    "parent": "issuer",
                    "default_days": 90,
                    "key_passphrase": self.secrets[0],
                    "parent_key_passphrase": self.secrets[1],
                    "archived_key_passphrases": {"generation": self.secrets[5]},
                }
            ],
        }
        self.item = {
            "name": "web01",
            "type": "tls_server",
            "common_name": "web01.example.test",
            "formats": ["pem", "pfx"],
            "pfx_passphrase": self.secrets[2],
            "passphrase": self.secrets[3],
            "key_passphrase": self.secrets[4],
            "fritzbox_deploy": {
                "username": "admin",
                "password": self.secrets[6],
                "validate_certs": False,
            },
        }
        self.result = {
            "changed": False,
            "name": "web01",
            "profile": "tls_server",
            "cert_path": "/tmp/pki/certs/web01/web01.pem",
            "formats": ["pem", "pfx"],
            "pkcs12_paths": {"pfx": "/tmp/pki/certs/web01/web01.pfx"},
        }

    def invoke(
        self,
        *,
        batch: bool = False,
        encoded: bool = False,
        mode: str = "success",
    ) -> dict[str, Any]:
        """Use the public module entry point, replacing only its file operation."""
        plugin = certificate_batch if batch else certificate
        operation_name = (
            "ensure_certificate_batch" if batch else "ensure_certificate_artifacts"
        )
        inputs = copy.deepcopy(self.inputs)
        # Newer controllers request invocation metadata; 2.20 always emits it.
        if "inject_invocation" in PASS_VARS:
            inputs["_ansible_inject_invocation"] = True
        key = "certificates" if batch else "certificate"
        inputs[key] = [self.item] if batch else self.item
        if encoded:
            inputs[key] = [json.dumps(self.item)] if batch else json.dumps(self.item)
            inputs["authorities"] = [json.dumps(item) for item in inputs["authorities"]]
        if mode == "invalid":
            inputs["force"] = "invalid-" + self.secrets[2]
        if mode == "check":
            inputs["_ansible_check_mode"] = True
        result = (
            {"changed": False, "results": [self.result], "issuer_groups": {"issuer": 1}}
            if batch
            else self.result
        )
        with (
            module_transport(inputs) as (output, log),
            patch.object(plugin, operation_name, return_value=result) as operation,
            self.assertRaises(SystemExit) as exited,
        ):
            if mode == "failure":
                operation.side_effect = ValueError(
                    "Certificate web01 CSR signing requires an issuing CA: "
                    + self.secrets[0]
                )
            plugin.main()
        self.assertEqual(
            exited.exception.code, 1 if mode in {"failure", "invalid"} else 0
        )
        if mode == "invalid" or (mode == "check" and not batch):
            operation.assert_not_called()
        for secret in self.secrets:
            self.assertNotIn(secret, module_diagnostics(output, log))
        decoded: dict[str, Any] = json.loads(output.getvalue())
        return decoded

    def test_single_and_batch_results_keep_names_formats_and_paths(self) -> None:
        """Registered results and invocation metadata must retain public values."""
        for batch in (False, True):
            for encoded in (False, True):
                with self.subTest(batch=batch, encoded=encoded):
                    result = self.invoke(batch=batch, encoded=encoded)
                    actual = result["results"][0] if batch else result
                    for key, value in self.result.items():
                        self.assertEqual(actual[key], value)
                    invocation = result["invocation"]["module_args"]
                    self.assertEqual(invocation["authorities"][0]["name"], "issuer")
                    if batch:
                        self.assertEqual(result["issuer_groups"], {"issuer": 1})

    def test_operation_errors_keep_the_certificate_name(self) -> None:
        """A domain error remains actionable while containing no secret values."""
        for batch in (False, True):
            with self.subTest(batch=batch):
                result = self.invoke(batch=batch, mode="failure")
                self.assertIn(
                    "Certificate web01 CSR signing requires an issuing CA",
                    result["msg"],
                )

    def test_argument_validation_errors_are_already_protected(self) -> None:
        """Constructor failures must not expose nested secrets in invocation data."""
        for batch in (False, True):
            with self.subTest(batch=batch):
                result = self.invoke(batch=batch, mode="invalid", encoded=True)
                self.assertTrue(result["failed"])

    def test_check_mode_does_not_leak_secrets(self) -> None:
        """Ansible can skip the module during construction before normal execution."""
        for batch in (False, True):
            with self.subTest(batch=batch):
                result = self.invoke(batch=batch, mode="check")
                self.assertEqual(bool(result.get("skipped")), not batch)


class PublicationRedactionTests(unittest.TestCase):
    """Publish real files through Ansible with reusable authority definitions."""

    def test_publication_results_and_failures(self) -> None:
        """Public paths survive; nested credentials stay protected on every exit."""
        secrets = ["issuer-test-secret", "parent-test-secret", "archived-test-secret"]
        for plugin in (publish, publish_archive):
            with (
                self.subTest(module=plugin.__name__),
                tempfile.TemporaryDirectory() as tmp,
            ):
                source = Path(tmp) / "certificate.cer"
                source.write_bytes(b"public certificate fixture")
                inputs: dict[str, Any] = {
                    "base_dir": tmp,
                    "dest": str(Path(tmp) / "certificates"),
                    "artifacts": [
                        {"src": str(source), "area": "aia", "file": "certificate.cer"}
                    ],
                    "authorities": [
                        {"name": "public-only"},
                        {
                            "name": "issuer",
                            "formats": ["cer"],
                            "key_passphrase": secrets[0],
                            "parent_key_passphrase": secrets[1],
                            "archived_key_passphrases": {"generation": secrets[2]},
                        },
                    ],
                }
                if "inject_invocation" in PASS_VARS:
                    inputs["_ansible_inject_invocation"] = True
                for mode in ("create", "repeat", "check", "failure", "invalid"):
                    with self.subTest(mode=mode):
                        if mode == "failure":
                            source.unlink()
                        if mode == "invalid":
                            inputs["force"] = "invalid-" + secrets[0]
                        inputs["_ansible_check_mode"] = mode == "check"
                        with (
                            module_transport(inputs) as (output, log),
                            self.assertRaises(SystemExit) as exited,
                        ):
                            plugin.main()
                        self.assertEqual(
                            exited.exception.code,
                            1 if mode in ("failure", "invalid") else 0,
                        )
                        for secret in secrets:
                            self.assertNotIn(secret, module_diagnostics(output, log))
                        result = json.loads(output.getvalue())
                        if mode in ("create", "repeat"):
                            self.assertEqual(result["path"], inputs["dest"])
                            self.assertEqual(result["changed"], mode == "create")
                            field = (
                                "published_paths"
                                if plugin is publish
                                else "archive_paths"
                            )
                            self.assertEqual(result[field], ["aia/certificate.cer"])
                        if mode == "failure":
                            self.assertIn("certificate.cer", result["msg"])
                        args = result["invocation"]["module_args"]
                        authority = args["authorities"][1]
                        self.assertEqual(authority["name"], "issuer")
                        self.assertEqual(authority["formats"], ["cer"])
