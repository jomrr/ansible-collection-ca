# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""CA path limits and external CA requests through the real issuance engine."""

from __future__ import annotations

import datetime
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_engine import (
    ensure_certificate_artifacts,
    ensure_certificate_batch,
    single_certificate_argument_spec,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509 import (
    ca_authority_argument_spec,
    ensure_x509,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_chain import _ordered_chain
from ansible_collections.jomrr.ca.plugins.module_utils._x509_constraints import (
    validate_issuer_constraints,
)
from ansible_collections.jomrr.ca.plugins.modules.authority import _authority_params
from ansible_collections.jomrr.ca.tests.integration.targets.authority.files.csr import (
    untrusted_csr,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class PathLengthTests(unittest.TestCase):
    """Exercise finite, absent and inherited limits with actual certificates."""

    def setUp(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())

    def certificate(
        self, name: str, path_length: int | None, issuer: x509.Certificate | None = None
    ) -> x509.Certificate:
        """Construct a CA with explicit constraints for a path validation case."""
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.datetime.now(datetime.UTC)
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer.subject if issuer else subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(True, path_length), critical=True)
            .sign(self.key, hashes.SHA256())
        )

    def test_path_limits(self) -> None:
        """Leaf issuance and wider child constraints still honor every ancestor."""
        for root_limit, issuer_limit, child_ca, accepted in (
            (1, 0, False, True),
            (1, 0, True, False),
            (1, None, True, False),
            (1, 5, True, False),
            (2, 1, True, True),
            (None, None, True, True),
            (None, 0, True, False),
        ):
            with self.subTest(root=root_limit, issuer=issuer_limit, ca=child_ca):
                root = self.certificate("root", root_limit)
                issuer = self.certificate("issuer", issuer_limit, root)
                params = {"name": "child", "basic_constraints": [f"CA:{child_ca}"]}
                subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "child")])
                if accepted:
                    validate_issuer_constraints(params, subject, [issuer, root])
                else:
                    with self.assertRaisesRegex(ValueError, "pathlen:.*exceeded"):
                        validate_issuer_constraints(params, subject, [issuer, root])

    def test_self_issued_does_not_consume_path_length(self) -> None:
        """A same-subject CA rollover does not consume a path length slot."""
        root = self.certificate("root", 1)
        issuer = self.certificate("issuer", 0, root)
        validate_issuer_constraints(
            {"name": "rollover", "basic_constraints": ["CA:TRUE", "pathlen:0"]},
            issuer.subject,
            [issuer, root],
        )

    def test_child_limit_is_intersected_with_parent_limit(self) -> None:
        """A wider child limit does not invalidate direct leaf issuance below it."""
        root = self.certificate("root", 1)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "child")])
        for constraints in (["CA:TRUE"], ["CA:TRUE", "pathlen:5"]):
            validate_issuer_constraints(
                {"name": "child", "basic_constraints": constraints}, subject, [root]
            )


class IssuanceConstraintTests(unittest.TestCase):
    """Check public dispatcher behavior and absence of rejected output material."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base)
        self.authority("root", "root")
        self.authority("issuer", "root")
        chain = _ordered_chain(str(self.base), "issuer")
        (self.base / "chains").mkdir()
        (self.base / "chains/issuer-ca-chain.pem").write_bytes(
            b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in chain)
        )
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenBao")])
            )
            .sign(self.key, hashes.SHA256())
        )

    def authority(self, name: str, parent: str, **overrides: Any) -> dict[str, Any]:
        """Create a managed CA using the module's real defaults and engine."""
        values = {
            key: spec.get("default")
            for key, spec in ca_authority_argument_spec().items()
        }
        values.update(
            base_dir=str(self.base),
            name=name,
            parent=parent,
            common_name=name,
            days=365,
            key_type="P-256",
            key_passphrase="test-passphrase",
            parent_key_passphrase="test-passphrase",
            owner=str(os.getuid()),
            group=str(os.getgid()),
            **overrides,
        )
        params, signed = _authority_params(values)
        return ensure_x509(params, signed=signed, authority=True)

    def request(self, issuer: str = "issuer") -> dict[str, Any]:
        """Build an external CA request with explicit certificate-signing usage."""
        params = {
            key: spec.get("default")
            for key, spec in single_certificate_argument_spec().items()
        }
        params.update(
            base_dir=str(self.base),
            owner=str(os.getuid()),
            group=str(os.getgid()),
            authorities=[
                {
                    "name": "root",
                    "parent": "root",
                    "key_passphrase": "test-passphrase",
                    "default_days": 90,
                },
                {
                    "name": "issuer",
                    "parent": "root",
                    "key_passphrase": "test-passphrase",
                    "default_days": 90,
                },
            ],
            certificate_types={"tls_server": {"issuer": issuer}},
            certificate={
                "name": "openbao",
                "common_name": "OpenBao",
                "type": "tls_server",
                "formats": ["pem"],
                "csr_content": self.csr.public_bytes(
                    serialization.Encoding.PEM
                ).decode(),
                "basic_constraints": ["CA:TRUE", "pathlen:0"],
                "key_usage": ["keyCertSign", "cRLSign"],
            },
        )
        return params

    def test_managed_authority_rejected_before_writes(self) -> None:
        """A pathlen:0 issuer must not create a subordinate key, CSR or certificate."""
        with self.assertRaisesRegex(ValueError, "pathlen:0.*exceeded"):
            self.authority("subca", "issuer")
        for name in ("private/subca-ca.key", "csr/subca-ca.csr", "ca/subca-ca.pem"):
            self.assertFalse((self.base / name).exists(), name)
        self.assertTrue(self.authority("direct", "root")["changed"])
        self.assertFalse(self.authority("direct", "root")["changed"])

    def test_external_ca_rejected_before_writes(self) -> None:
        """An external CA CSR is subject to the same issuer path constraints."""
        with self.assertRaisesRegex(ValueError, "pathlen:0.*exceeded"):
            ensure_certificate_artifacts(self.request())
        self.assertFalse((self.base / "csr/openbao.csr").exists())
        self.assertFalse((self.base / "certs/openbao").exists())

    def test_root_can_sign_external_ca(self) -> None:
        """A root with room for an intermediate signs a CA CSR idempotently."""
        params = self.request("root")
        self.assertTrue(ensure_certificate_artifacts(params)["cert_changed"])
        self.assertFalse(ensure_certificate_artifacts(params)["changed"])
        root = x509.load_pem_x509_certificate(
            (self.base / "ca/root-ca.pem").read_bytes()
        )
        issued = x509.load_pem_x509_certificate(
            (self.base / "certs/openbao/openbao.pem").read_bytes()
        )
        issued.verify_directly_issued_by(root)
        self.assertEqual(issued.subject, self.csr.subject)
        self.assertEqual(
            issued.extensions.get_extension_for_class(x509.BasicConstraints).value,
            x509.BasicConstraints(True, 0),
        )
        self.assertFalse((self.base / "certs/openbao/openbao.key").exists())

    def test_batch_preflights_each_request(self) -> None:
        """A forbidden CA does not leave an earlier certificate in its batch group."""
        params = self.request()
        params["certificates"] = [
            {"name": "web", "type": "tls_server", "common_name": "web.example.test"},
            params.pop("certificate"),
        ]
        with self.assertRaisesRegex(ValueError, "pathlen:0.*exceeded"):
            ensure_certificate_batch(params)
        self.assertFalse((self.base / "certs/web").exists())

    def test_self_issued_rollover_chain_reaches_root(self) -> None:
        """Same subject names do not hide the signing root's inherited limit."""
        self.authority("rollover", "root", subject_ordered=[{"CN": "root"}])
        chain = _ordered_chain(str(self.base), "rollover")
        self.assertEqual(len(chain), 2)
        chain[0].verify_directly_issued_by(chain[1])

    def identity_request(self) -> dict[str, Any]:
        """Request unapproved identities with a correctly signed external key."""
        self.csr = untrusted_csr(self.key)
        params = self.request()
        params["certificate_types"] = {"identity": {"issuer": "issuer"}}
        params["subject"] = {"organization": "Approved Organization"}
        params["certificate"].update(type="identity", common_name="Max Muster")
        del params["certificate"]["basic_constraints"]
        del params["certificate"]["key_usage"]
        return params

    def test_csr_identities_come_only_from_task(self) -> None:
        """Neither missing nor empty SANs trust identities requested in a CSR."""
        params = self.identity_request()
        expected_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Approved Organization"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Max Muster"),
            ]
        )
        overrides: list[dict[str, Any]] = [
            {},
            {"san": []},
            {"san": ["email:max@example.test"]},
        ]
        for override in overrides:
            with self.subTest(override=override):
                params["certificate"].update(override)
                ensure_certificate_artifacts(params)
                cert = x509.load_pem_x509_certificate(
                    (self.base / "certs/openbao/openbao.pem").read_bytes()
                )
                self.assertEqual(cert.subject, expected_subject)
                self.assertEqual(cert.public_key(), self.key.public_key())
                self.assertIn(
                    x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"),
                    cert.extensions.get_extension_for_class(
                        x509.ExtendedKeyUsage
                    ).value,
                )
                if override.get("san"):
                    san = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                    self.assertEqual(
                        list(san.value), [x509.RFC822Name("max@example.test")]
                    )
                    self.assertFalse(san.critical)
                else:
                    with self.assertRaises(x509.ExtensionNotFound):
                        cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )
                self.assertFalse(ensure_certificate_artifacts(params)["changed"])

    def test_csr_requires_approved_subject_and_matching_cn(self) -> None:
        """Incomplete or mismatched approvals fail before writing artifacts."""
        params = self.identity_request()
        for common_name, error in (
            ("", "subject_ordered or common_name is required"),
            ("Another User", "does not match"),
        ):
            with self.subTest(common_name=common_name):
                params["certificate"]["common_name"] = common_name
                with self.assertRaisesRegex(ValueError, error):
                    ensure_certificate_artifacts(params)
                self.assertFalse((self.base / "csr/openbao.csr").exists())
                self.assertFalse((self.base / "certs/openbao").exists())

    def test_ordered_subject_and_profile_sans_in_batch(self) -> None:
        """An explicit subject replaces the request; profile SAN defaults survive."""
        params = self.identity_request()
        certificate = params.pop("certificate")
        certificate.pop("common_name")
        certificate["subject_ordered"] = [{"CN": "Approved User"}, {"O": "Approved"}]
        params["certificate_types"]["tls_server"] = {"issuer": "issuer"}
        params["certificates"] = [
            certificate,
            {
                **certificate,
                "name": "web",
                "type": "tls_server",
                "common_name": "Max Muster",
                "subject_ordered": [],
            },
        ]
        self.assertTrue(ensure_certificate_batch(params)["changed"])
        self.assertFalse(ensure_certificate_batch(params)["changed"])
        issued = x509.load_pem_x509_certificate(
            (self.base / "certs/openbao/openbao.pem").read_bytes()
        )
        self.assertEqual(issued.subject.rfc4514_string(), "O=Approved,CN=Approved User")
        web = x509.load_pem_x509_certificate(
            (self.base / "certs/web/web.pem").read_bytes()
        )
        self.assertEqual(
            list(
                web.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
            ),
            [x509.DNSName("Max Muster")],
        )
