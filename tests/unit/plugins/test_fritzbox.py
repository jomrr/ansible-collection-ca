# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: MIT
"""FRITZ!Box module contracts with the device boundary simulated."""

from __future__ import annotations

import datetime
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import Mock, patch

from ansible_collections.jomrr.ca.plugins.modules import fritzbox_deploy
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from collections.abc import Callable


class ModuleResult(BaseException):
    """Model Ansible's terminating result without entering module error handlers."""

    def __init__(self, **result: Any) -> None:
        super().__init__()
        self.result = result


def finish_module(**result: Any) -> None:
    """Preserve Ansible result arguments when terminating the test module."""
    raise ModuleResult(**result)


def certificate(key: rsa.RSAPrivateKey, serial: int) -> x509.Certificate:
    """Create a disposable device certificate without external services."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fritz.box")])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


class FritzBoxTests(unittest.TestCase):
    """Exercise idempotence, failure handling and the original TLS default."""

    def setUp(self) -> None:
        self.directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.directory)
        self.path = Path(self.directory) / "bundle.pem"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.desired = certificate(key, 1)
        self.previous = certificate(key, 2)
        self.path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            + self.desired.public_bytes(serialization.Encoding.PEM)
        )
        self.device = Mock()
        self.device.current_certificate.return_value = self.previous
        self.inputs: dict[str, Any] = {
            "base_dir": self.directory,
            "name": "fritzbox",
            "bundle_path": str(self.path),
            "username": "test-user",
            "password": "recognizable-test-password",
        }
        self.module = Mock()
        self.module.exit_json.side_effect = finish_module
        self.module.fail_json.side_effect = finish_module

    def invoke(self) -> dict[str, Any]:
        """Run the public entry point using its own argument defaults."""

        def make_module(**kwargs: Any) -> Mock:
            self.module.params = {
                key: spec.get("default")
                for key, spec in kwargs["argument_spec"].items()
            }
            self.module.params.update(self.inputs)
            return self.module

        with (
            patch.object(fritzbox_deploy, "AnsibleModule", side_effect=make_module),
            patch.object(fritzbox_deploy, "FritzBoxClient", return_value=self.device),
            self.assertRaises(ModuleResult) as result,
        ):
            cast("Callable[[], None]", fritzbox_deploy.main)()
        return result.exception.result

    def test_upload_and_repeat(self) -> None:
        """Different device state uploads once; the resulting state is unchanged."""

        def import_bundle(bundle: bytes) -> None:
            self.assertEqual(bundle, self.path.read_bytes())
            self.device.current_certificate.return_value = self.desired

        self.device.import_certificate.side_effect = import_bundle
        self.assertTrue(self.invoke()["changed"])
        self.assertFalse(self.invoke()["changed"])
        self.device.import_certificate.assert_called_once()
        self.device.login.assert_called_once()

    def test_force(self) -> None:
        """Force retains the source module's unconditional deployment behavior."""
        self.device.current_certificate.return_value = self.desired
        self.inputs["force"] = True
        self.assertTrue(self.invoke()["changed"])
        self.device.import_certificate.assert_called_once()

    def test_failure_redacts_password(self) -> None:
        """A failed deployment masks the supplied password and closes the session."""
        self.device.import_certificate.side_effect = RuntimeError(
            "rejected recognizable-test-password"
        )
        result = self.invoke()
        self.assertNotIn("recognizable-test-password", result["msg"])
        self.assertIn("rejected", result["msg"])
        self.device.logout.assert_called_once()

    def test_invalid_bundle_does_not_connect(self) -> None:
        """Invalid input fails before logging into a device."""
        self.path.write_bytes(b"not a certificate")
        self.assertIn("does not contain a certificate", self.invoke()["msg"])
        self.device.login.assert_not_called()

    def test_original_tls_default(self) -> None:
        """Absent validate_certs keeps support for default self-signed devices."""
        self.invoke()
        self.assertIs(self.module.params["validate_certs"], False)
