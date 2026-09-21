# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Missing managed-node dependencies must produce an Ansible failure."""

from __future__ import annotations

import importlib
import unittest
from unittest.mock import Mock, patch

from ansible_collections.jomrr.ca.plugins.module_utils import _dependency


class MissingCryptographyTests(unittest.TestCase):
    """Exercise dependency failures through each affected module entry point."""

    def test_module_failure(self) -> None:
        """A missing library fails before operations access module parameters."""
        for name in (
            "authority",
            "certificate",
            "certificate_batch",
            "chain",
            "crl",
            "fritzbox_deploy",
        ):
            with self.subTest(module=name):
                plugin = importlib.import_module(
                    f"ansible_collections.jomrr.ca.plugins.modules.{name}"
                )
                module = Mock()
                module.fail_json.side_effect = SystemExit(1)
                with (
                    patch.object(plugin, "AnsibleModule", return_value=module),
                    patch.object(
                        _dependency,
                        "CRYPTOGRAPHY_IMPORT_ERROR",
                        "No module named 'cryptography'",
                    ),
                    self.assertRaises(SystemExit),
                ):
                    plugin.main()
                module.fail_json.assert_called_once_with(
                    msg="Failed to import cryptography: No module named 'cryptography'"
                )
                module.exit_json.assert_not_called()
