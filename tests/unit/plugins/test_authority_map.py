# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: MIT
"""Controller filter contracts through the collection import path."""

from __future__ import annotations

import unittest

from ansible.errors import AnsibleFilterError
from ansible_collections.jomrr.ca.plugins.filter.authority_map import FilterModule


class AuthorityMapTests(unittest.TestCase):
    """Validate the migrated filter's accepted and rejected inputs."""

    def test_preserves_input(self) -> None:
        """Authorities are indexed without rewriting their dictionaries."""
        root = {"name": "root", "parent": "root"}
        issuer = {"name": "issuer", "parent": "root"}
        result = FilterModule().filters()["authority_map"]([root, issuer])
        self.assertEqual(result, {"root": root, "issuer": issuer})
        self.assertIs(result["root"], root)
        self.assertEqual(root, {"name": "root", "parent": "root"})

    def test_empty(self) -> None:
        """Null and empty input retain the source filter's empty-map behavior."""
        cases: list[list[dict[str, str]] | None] = [None, []]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(FilterModule().filters()["authority_map"](value), {})

    def test_invalid_graphs(self) -> None:
        """Reject bad shapes, unsafe names, duplicate names and missing parents."""
        root = {"name": "root", "parent": "root"}
        for value in (
            "root",
            ["root"],
            [root, root],
            [{"name": "root", "parent": "missing"}],
            [{"name": "../escape", "parent": "../escape"}],
        ):
            with self.subTest(value=value), self.assertRaises(AnsibleFilterError):
                FilterModule().filters()["authority_map"](value)
