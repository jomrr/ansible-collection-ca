# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Inventory-to-certificate filter contracts."""

from copy import deepcopy
from unittest import TestCase

from ansible.errors import AnsibleFilterError
from ansible_collections.jomrr.ca.plugins.filter.host_certificates import (
    host_certificates,
)


class HostCertificatesTests(TestCase):
    """Check exact output, configurable defaults and input boundaries."""

    def test_two_hosts(self) -> None:
        """Produce sorted complete definitions, including IPv4 and IPv6 SANs."""
        hosts = ["web02", "web01"]
        hostvars = {
            "web01": {"ansible_host": "192.0.2.10"},
            "web02": {"ansible_host": "2001:db8::20"},
            "unselected": {"ansible_host": "not-an-ip"},
        }
        before = deepcopy((hosts, hostvars))
        result = host_certificates(hosts, hostvars, "example.test")
        self.assertEqual(
            result,
            [
                {
                    "name": "web01",
                    "type": "tls_server",
                    "common_name": "web01.example.test",
                    "key_type": "P-384",
                    "san": ["DNS:web01.example.test", "DNS:web01", "IP:192.0.2.10"],
                    "formats": ["pem", "der", "txt", "fullchain"],
                },
                {
                    "name": "web02",
                    "type": "tls_server",
                    "common_name": "web02.example.test",
                    "key_type": "P-384",
                    "san": ["DNS:web02.example.test", "DNS:web02", "IP:2001:db8::20"],
                    "formats": ["pem", "der", "txt", "fullchain"],
                },
            ],
        )
        self.assertEqual((hosts, hostvars), before)
        first_formats = result[0]["formats"]
        assert isinstance(first_formats, list)
        first_formats.append("cer")
        self.assertEqual(result[1]["formats"], ["pem", "der", "txt", "fullchain"])

    def test_overrides_and_empty_hosts(self) -> None:
        """Copy overrides, collapse duplicate hosts and retain empty input."""
        hostvars = {"web01": {"ansible_host": "192.0.2.10"}}
        formats = ["pem", "bundle"]
        result = host_certificates(
            ["web01", "web01"], hostvars, "example.test", "P-256", formats
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["key_type"], "P-256")
        self.assertEqual(result[0]["formats"], formats)
        result_formats = result[0]["formats"]
        assert isinstance(result_formats, list)
        result_formats.append("cer")
        self.assertEqual(formats, ["pem", "bundle"])
        self.assertEqual(host_certificates([], {}, "example.test"), [])
        self.assertEqual(host_certificates([], {}), [])

    def test_host_variables(self) -> None:
        """Use another DNS domain, merge host options and retain independent data."""
        overrides = {
            "name": "client02",
            "type": "tls_client",
            "key_type": "RSA",
            "key_size": 3072,
            "formats": [],
            "san": [
                "DNS:alias.other.test",
                "DNS:web02.other.test",
                "DNS:alias.other.test",
            ],
            "subject": {"organization": "Example"},
        }
        hostvars = {
            "web01": {"ansible_host": "192.0.2.10"},
            "web02": {
                "ansible_host": "2001:db8::20",
                "fqdn": "web02.other.test",
                "ca_certificate": overrides,
            },
        }
        before = deepcopy(hostvars)
        result = host_certificates(["web02", "web01"], hostvars, "example.test")
        self.assertEqual(
            result[0],
            {
                "name": "client02",
                "type": "tls_client",
                "common_name": "web02.other.test",
                "key_type": "RSA",
                "key_size": 3072,
                "san": [
                    "DNS:web02.other.test",
                    "DNS:web02",
                    "IP:2001:db8::20",
                    "DNS:alias.other.test",
                ],
                "formats": [],
                "subject": {"organization": "Example"},
            },
        )
        self.assertEqual(result[1]["name"], "web01")
        self.assertEqual(result[1]["common_name"], "web01.example.test")
        self.assertEqual(host_certificates(["web02"], hostvars), result[:1])
        self.assertEqual(hostvars, before)
        subject = result[0]["subject"]
        assert isinstance(subject, dict)
        subject["organization"] = "Changed"
        self.assertEqual(hostvars, before)
        overrides["common_name"] = "Client Two"
        result = host_certificates(["web02"], hostvars)
        self.assertEqual(result[0]["common_name"], "Client Two")
        self.assertEqual(
            result[0]["san"],
            [
                "DNS:web02.other.test",
                "DNS:web02",
                "IP:2001:db8::20",
                "DNS:alias.other.test",
            ],
        )
        selected = {
            "web02": {
                "ansible_host": "2001:db8::20",
                "fqdn": "ignored.example.test",
                "ca_certificate": {"type": "ignored"},
                "inventory_fqdn": "web02.other.test",
                "pki_certificate": overrides,
            },
        }
        self.assertEqual(
            host_certificates(
                ["web02"],
                selected,
                fqdn_var="inventory_fqdn",
                overrides_var="pki_certificate",
            ),
            result,
        )
        self.assertEqual(
            host_certificates(
                ["web01"],
                hostvars,
                "example.test",
                fqdn_var="inventory_fqdn",
                overrides_var="pki_certificate",
            ),
            host_certificates(["web01"], hostvars, "example.test"),
        )

    def test_invalid_inputs(self) -> None:
        """Reject invalid shapes and addresses without exposing hostvars."""
        hostvars = {"web01": {"ansible_host": "192.0.2.10"}}
        for hosts, variables, domain, options in (
            ("web01", hostvars, "example.test", {}),
            ([None], hostvars, "example.test", {}),
            (["web01"], None, "example.test", {}),
            (["web01"], {}, "example.test", {}),
            (["web01"], {"web01": {}}, "example.test", {}),
            (
                ["web01"],
                {"web01": {"ansible_host": "web.example.test"}},
                "example.test",
                {},
            ),
            (["web01"], hostvars, "", {}),
            (["web01"], hostvars, None, {}),
            (["web01"], hostvars, "example.test", {"key_type": ""}),
            (["web01"], hostvars, "example.test", {"formats": "pem"}),
            (["web01"], hostvars, "example.test", {"formats": [1]}),
            (["web01"], hostvars, "example.test", {"fqdn_var": ""}),
            (["web01"], hostvars, "example.test", {"fqdn_var": None}),
            (["web01"], hostvars, "example.test", {"overrides_var": []}),
            (["web01"], hostvars, "example.test", {"overrides_var": ""}),
            (["web01"], hostvars, "example.test", {"fqdn_vars": "fqdn"}),
        ):
            with (
                self.subTest(hosts=hosts, domain=domain, options=options),
                self.assertRaises(AnsibleFilterError),
            ):
                host_certificates(hosts, variables, domain, **options)

        invalid_variables: tuple[dict[str, object], ...] = (
            {"fqdn": ""},
            {"fqdn": None},
            {"fqdn": 123},
            {"ca_certificate": []},
            {"ca_certificate": {1: "invalid"}},
            {"ca_certificate": {"name": ""}},
            {"ca_certificate": {"type": False}},
            {"ca_certificate": {"common_name": None}},
            {"ca_certificate": {"key_type": []}},
            {"ca_certificate": {"formats": "pem"}},
            {"ca_certificate": {"san": [1]}},
            {
                "ca_certificate": {
                    "san": "invalid",
                    "key_passphrase": "synthetic-secret",
                }
            },
        )
        for override in invalid_variables:
            with (
                self.subTest(override=override),
                self.assertRaises(AnsibleFilterError) as caught,
            ):
                host_certificates(
                    ["web01"],
                    {"web01": {"ansible_host": "192.0.2.10", **override}},
                    "example.test",
                )
            self.assertNotIn("synthetic-secret", str(caught.exception))

        with self.assertRaisesRegex(AnsibleFilterError, "Duplicate certificate name"):
            host_certificates(
                ["web01", "web02"],
                {
                    "web01": {"ansible_host": "192.0.2.10"},
                    "web02": {
                        "ansible_host": "192.0.2.20",
                        "ca_certificate": {"name": "web01"},
                    },
                },
                "example.test",
            )

        with self.assertRaises(AnsibleFilterError) as caught:
            host_certificates(
                ["web01"],
                {"web01": {"ansible_password": "synthetic-secret"}},
                "example.test",
            )
        self.assertNotIn("synthetic-secret", str(caught.exception))
