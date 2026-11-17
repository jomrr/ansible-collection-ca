# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Artifact manifests match issuance and keep private files opt-in."""

from copy import deepcopy
from unittest import TestCase

from ansible.errors import AnsibleFilterError
from ansible_collections.jomrr.ca.plugins.filter.artifacts import artifacts


class ArtifactsTests(TestCase):
    """Check the public manifest contract without duplicating path helpers."""

    def test_one_authority_two_certificates(self) -> None:
        """List all public outputs and only the opted-in certificate's secrets."""
        authorities = [{"name": "root", "formats": ["pem", "der", "cer", "txt"]}]
        certificates = [
            {
                "name": "web01",
                "type": "tls_server",
                "formats": ["fullchain", "bundle", "pfx"],
            },
            {
                "name": "scanner",
                "type": "tls_server",
                "formats": ["cer", "bundle", "pfx", "p12", "fritzbox", "cer"],
                "publish_private": True,
            },
        ]
        before = deepcopy((certificates, authorities))
        expected = [
            ("ca/root-ca.cer", "root", "cer", False),
            ("ca/root-ca.der", "root", "der", False),
            ("ca/root-ca.pem", "root", "pem", False),
            ("ca/root-ca.txt", "root", "txt", False),
            ("certs/scanner/scanner-bundle.pem", "scanner", "bundle", True),
            ("certs/scanner/scanner-chain.pem", "scanner", "chain", False),
            ("certs/scanner/scanner-fritzbox.pem", "scanner", "fritzbox", True),
            ("certs/scanner/scanner.cer", "scanner", "cer", False),
            ("certs/scanner/scanner.key", "scanner", "key", True),
            ("certs/scanner/scanner.p12", "scanner", "p12", True),
            ("certs/scanner/scanner.pem", "scanner", "pem", False),
            ("certs/scanner/scanner.pfx", "scanner", "pfx", True),
            ("certs/web01/web01-chain.pem", "web01", "chain", False),
            ("certs/web01/web01-fullchain.pem", "web01", "fullchain", False),
            ("certs/web01/web01.pem", "web01", "pem", False),
        ]
        self.assertEqual(
            artifacts(certificates, authorities),
            [
                {"src": src, "owner": owner, "format": fmt, "secret": secret}
                for src, owner, fmt, secret in expected
            ],
        )
        self.assertEqual((certificates, authorities), before)

    def test_profile_defaults_and_empty_formats(self) -> None:
        """Defaults agree with profiles; explicit empty formats add no exports."""
        for profile, private in (("identity", "pfx"), ("fritzbox", "fritzbox")):
            item: dict[str, object] = {"name": "host", "type": profile}
            public = artifacts([item], [])
            self.assertEqual(
                {entry["format"] for entry in public}, {"pem", "der", "txt", "chain"}
            )
            item["publish_private"] = True
            self.assertEqual(
                {entry["format"] for entry in artifacts([item], [])},
                {"pem", "der", "txt", "chain", "key", private},
            )
        self.assertEqual(
            {entry["format"] for entry in artifacts([], [{"name": "root"}])},
            {"pem", "der", "txt"},
        )
        result = artifacts(
            [{"name": "host", "type": "tls_server", "formats": []}],
            [{"name": "root", "formats": []}],
        )
        self.assertEqual([entry["format"] for entry in result], ["pem", "chain", "pem"])
        self.assertEqual(artifacts([], []), [])

    def test_external_csr_has_no_local_key(self) -> None:
        """Opt-in cannot list a private key that belongs to an external CA."""
        for source in ("csr_path", "csr_content"):
            result = artifacts(
                [
                    {
                        "name": "external",
                        "type": "issuing_ca",
                        source: "external-csr",
                        "publish_private": True,
                    }
                ],
                [],
            )
            self.assertFalse(any(entry["secret"] for entry in result))
            self.assertEqual(
                {entry["format"] for entry in result},
                {"pem", "der", "txt", "chain", "fullchain"},
            )

    def test_invalid_definitions(self) -> None:
        """Fail closed on invalid opt-in, unsupported layouts and malformed input."""
        for override in (
            {"name": "../escape"},
            {"name": ".."},
            {"publish_private": "false"},
            {"publish_private": 1},
            {"formats": "pem"},
            {"formats": ["unknown"]},
            {"formats": [1]},
            {"type": "unknown"},
            {"output_dir": "/srv/custom"},
            {"formats": ["bundle"], "csr_path": "/tmp/request.csr"},
        ):
            with self.subTest(override=override), self.assertRaises(AnsibleFilterError):
                artifacts([{"name": "host", "type": "tls_server", **override}], [])
        for certificates, authorities in (
            ({}, []),
            ([], {}),
            (["host"], []),
            ([], ["root"]),
            ([{"name": "host"}], []),
            ([], [{"name": "root"}, {"name": "root"}]),
        ):
            with (
                self.subTest(certificates=certificates, authorities=authorities),
                self.assertRaises(AnsibleFilterError),
            ):
                artifacts(certificates, authorities)
