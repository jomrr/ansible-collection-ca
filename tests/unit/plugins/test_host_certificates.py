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
        result[0]["formats"].append("cer")
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
        result[0]["formats"].append("cer")
        self.assertEqual(formats, ["pem", "bundle"])
        self.assertEqual(host_certificates([], {}, "example.test"), [])

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
            (["web01"], hostvars, "example.test", {"key_type": ""}),
            (["web01"], hostvars, "example.test", {"formats": "pem"}),
            (["web01"], hostvars, "example.test", {"formats": [1]}),
        ):
            with (
                self.subTest(hosts=hosts, domain=domain, options=options),
                self.assertRaises(AnsibleFilterError),
            ):
                host_certificates(hosts, variables, domain, **options)

        with self.assertRaises(AnsibleFilterError) as caught:
            host_certificates(
                ["web01"],
                {"web01": {"ansible_password": "synthetic-secret"}},
                "example.test",
            )
        self.assertNotIn("synthetic-secret", str(caught.exception))
