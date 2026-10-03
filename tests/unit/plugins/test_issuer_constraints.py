# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""CA path limits and external CA requests through the real issuance engine."""

from __future__ import annotations

import datetime
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_engine import (
    ensure_certificate_artifacts,
    ensure_certificate_batch,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_chain import ordered_chain
from ansible_collections.jomrr.ca.plugins.module_utils._x509_constraints import (
    validate_issuer_constraints,
)
from ansible_collections.jomrr.ca.tests.integration.targets.authority.files.csr import (
    untrusted_csr,
)
from ansible_collections.jomrr.ca.tests.unit.plugins.certificate_fixture import (
    CertificateFixture,
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
                constraints = [f"CA:{child_ca}"]
                subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "child")])
                if accepted:
                    validate_issuer_constraints(
                        "child", constraints, subject, [issuer, root]
                    )
                else:
                    with self.assertRaisesRegex(ValueError, "pathlen:.*exceeded"):
                        validate_issuer_constraints(
                            "child",
                            constraints,
                            subject,
                            [issuer, root],
                        )

    def test_self_issued_does_not_consume_path_length(self) -> None:
        """A same-subject CA rollover does not consume a path length slot."""
        root = self.certificate("root", 1)
        issuer = self.certificate("issuer", 0, root)
        validate_issuer_constraints(
            "rollover",
            ["CA:TRUE", "pathlen:0"],
            issuer.subject,
            [issuer, root],
        )

    def test_child_limit_is_intersected_with_parent_limit(self) -> None:
        """A wider child limit does not invalidate direct leaf issuance below it."""
        root = self.certificate("root", 1)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "child")])
        for constraints in (["CA:TRUE"], ["CA:TRUE", "pathlen:5"]):
            validate_issuer_constraints("child", constraints, subject, [root])


class IssuanceConstraintTests(unittest.TestCase):
    """Check public dispatcher behavior and absence of rejected output material."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base)
        self.ca = CertificateFixture(self.base)

    def test_managed_authority_rejected_before_writes(self) -> None:
        """A pathlen:0 issuer must not create a subordinate key, CSR or certificate."""
        with self.assertRaisesRegex(ValueError, "pathlen:0.*exceeded"):
            self.ca.authority("subca", "issuer")
        for name in ("private/subca-ca.key", "csr/subca-ca.csr", "ca/subca-ca.pem"):
            self.assertFalse((self.base / name).exists(), name)
        self.assertTrue(self.ca.authority("direct", "root")["changed"])
        self.assertFalse(self.ca.authority("direct", "root")["changed"])

    def test_external_ca_rejected_before_writes(self) -> None:
        """An external CA CSR is subject to the same issuer path constraints."""
        for params in (self.ca.request(), self.issuing_ca_request("issuer")):
            with (
                self.subTest(profile=params["certificate"]["type"]),
                self.assertRaisesRegex(ValueError, "pathlen:0.*exceeded"),
            ):
                ensure_certificate_artifacts(params)
        self.assertFalse((self.base / "csr/openbao.csr").exists())
        self.assertFalse((self.base / "certs/openbao").exists())

    def issuing_ca_request(self, issuer: str) -> dict[str, Any]:
        """Use the issuing CA profile with its default extensions and exports."""
        params = self.ca.request(issuer)
        params["certificate_types"] = {"issuing_ca": {"issuer": issuer}}
        params["certificate"]["type"] = "issuing_ca"
        for key in ("basic_constraints", "key_usage", "formats"):
            del params["certificate"][key]
        return params

    def test_root_can_sign_external_ca(self) -> None:
        """CA requests retain explicit extensions without inheriting leaf defaults."""
        root = x509.load_pem_x509_certificate(
            (self.base / "ca/root-ca.pem").read_bytes()
        )
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenBao CA")])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(self.ca.key, hashes.SHA256())
        )
        overrides: tuple[dict[str, list[str]], ...] = (
            {},
            {"extended_key_usage": [], "san": []},
            {
                "extended_key_usage": ["clientAuth"],
                "san": ["URI:https://pki.example.test"],
            },
        )
        for profile in ("tls_server", "tls_client", "issuing_ca"):
            for index, override in enumerate(overrides):
                with self.subTest(profile=profile, override=override):
                    params = (
                        self.issuing_ca_request("root")
                        if profile == "issuing_ca"
                        else self.ca.request("root")
                    )
                    params["certificate_types"] = {profile: {"issuer": "root"}}
                    params["certificate"].update(
                        name=f"external-{profile}-{index}",
                        type=profile,
                        common_name="OpenBao CA",
                        csr_content=csr.public_bytes(
                            serialization.Encoding.PEM
                        ).decode(),
                        **override,
                    )
                    result = ensure_certificate_artifacts(params)
                    self.assertTrue(result["cert_changed"])
                    self.assertFalse(ensure_certificate_artifacts(params)["changed"])
                    issued = x509.load_pem_x509_certificate(
                        Path(result["cert_path"]).read_bytes()
                    )
                    issued.verify_directly_issued_by(root)
                    self.assertEqual(issued.subject, subject)
                    constraints = issued.extensions.get_extension_for_class(
                        x509.BasicConstraints
                    )
                    self.assertEqual(constraints.value, x509.BasicConstraints(True, 0))
                    usage = issued.extensions.get_extension_for_class(x509.KeyUsage)
                    self.assertTrue(usage.critical)
                    self.assertTrue(usage.value.key_cert_sign)
                    self.assertTrue(usage.value.crl_sign)
                    if override.get("extended_key_usage"):
                        self.assertEqual(
                            list(
                                issued.extensions.get_extension_for_class(
                                    x509.ExtendedKeyUsage
                                ).value
                            ),
                            [x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2")],
                        )
                        self.assertEqual(
                            list(
                                issued.extensions.get_extension_for_class(
                                    x509.SubjectAlternativeName
                                ).value
                            ),
                            [
                                x509.UniformResourceIdentifier(
                                    "https://pki.example.test"
                                )
                            ],
                        )
                    else:
                        for extension in (
                            x509.ExtendedKeyUsage,
                            x509.SubjectAlternativeName,
                        ):
                            with self.assertRaises(x509.ExtensionNotFound):
                                issued.extensions.get_extension_for_class(extension)
                    if profile == "issuing_ca":
                        chain = x509.load_pem_x509_certificates(
                            Path(result["fullchain_path"]).read_bytes()
                        )
                        self.assertEqual(chain, [issued, root])
                    self.assertFalse(
                        Path(result["cert_path"]).with_suffix(".key").exists()
                    )

    def test_batch_preflights_each_request(self) -> None:
        """A forbidden CA does not leave an earlier certificate in its batch group."""
        params = self.ca.request()
        params["certificates"] = [
            {"name": "web", "type": "tls_server", "common_name": "web.example.test"},
            params.pop("certificate"),
        ]
        with self.assertRaisesRegex(ValueError, "pathlen:0.*exceeded"):
            ensure_certificate_batch(params)
        self.assertFalse((self.base / "certs/web").exists())

    def test_self_issued_rollover_chain_reaches_root(self) -> None:
        """Same subject names do not hide the signing root's inherited limit."""
        self.ca.authority("rollover", "root", subject_ordered=[{"CN": "root"}])
        chain = ordered_chain(str(self.base), "rollover")
        self.assertEqual(len(chain), 2)
        chain[0].verify_directly_issued_by(chain[1])

    def identity_request(self) -> dict[str, Any]:
        """Request unapproved identities with a correctly signed external key."""
        self.ca.csr = untrusted_csr(self.ca.key)
        params = self.ca.request()
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
                self.assertEqual(cert.public_key(), self.ca.key.public_key())
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
        params["certificates"].append(
            {
                **params["certificates"][1],
                "name": "web-empty",
                "san": [],
                "extended_key_usage": [],
            }
        )
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
        self.assertEqual(
            list(web.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value),
            [x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")],
        )
        empty = x509.load_pem_x509_certificate(
            (self.base / "certs/web-empty/web-empty.pem").read_bytes()
        )
        for extension in (x509.ExtendedKeyUsage, x509.SubjectAlternativeName):
            with self.assertRaises(x509.ExtensionNotFound):
                empty.extensions.get_extension_for_class(extension)
