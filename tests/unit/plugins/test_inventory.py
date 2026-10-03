# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared inventory metadata must converge across different module inputs."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from ansible_collections.jomrr.ca.plugins.module_utils._inventory import (
    compose_inventory,
    compose_inventory_if_configured,
    write_composed_inventory,
)


class InventoryTests(TestCase):
    """Exercise real inventory persistence, defaults, updates and read failures."""

    def test_base_url_is_retained_until_explicitly_replaced(self) -> None:
        """Missing and empty input preserve metadata without reporting changes."""
        with TemporaryDirectory() as directory:
            params = {"base_dir": directory, "ca_name": "test"}
            path = Path(directory) / "inventory/ca-inventory.json"
            self.assertTrue(compose_inventory_if_configured(params))
            self.assertEqual(json.loads(path.read_text())["base_url"], "")
            self.assertFalse(compose_inventory_if_configured(params))
            for url in ("http://pki.example.test", "https://pki.example.test/new"):
                self.assertTrue(
                    write_composed_inventory(
                        base_dir=directory, ca_name="test", base_url=url
                    )
                )
                before = path.read_bytes()
                self.assertFalse(
                    write_composed_inventory(
                        base_dir=directory, ca_name="test", base_url=url
                    )
                )
                self.assertFalse(compose_inventory_if_configured(params))
                self.assertFalse(
                    write_composed_inventory(
                        base_dir=directory, ca_name="test", base_url=""
                    )
                )
                self.assertEqual(
                    compose_inventory(**params, base_url="")["base_url"], url
                )
                self.assertEqual(path.read_bytes(), before)

    def test_invalid_or_unreadable_inventory_is_not_treated_as_absent(self) -> None:
        """A failed metadata read must not silently replace the inventory."""
        with TemporaryDirectory() as directory:
            write_composed_inventory(base_dir=directory, ca_name="test", base_url="")
            path = Path(directory) / "inventory/ca-inventory.json"
            for content, error in (
                (b"invalid JSON", ValueError),
                (b'{"base_url": 42}', TypeError),
            ):
                with self.subTest(content=content):
                    path.write_bytes(content)
                    with self.assertRaises(error):
                        write_composed_inventory(
                            base_dir=directory, ca_name="test", base_url=""
                        )
                    self.assertEqual(path.read_bytes(), content)
            with (
                patch(
                    "ansible_collections.jomrr.ca.plugins.module_utils."
                    "_inventory_store.read_file",
                    side_effect=PermissionError("denied"),
                ),
                self.assertRaises(PermissionError),
            ):
                write_composed_inventory(
                    base_dir=directory, ca_name="test", base_url=""
                )
