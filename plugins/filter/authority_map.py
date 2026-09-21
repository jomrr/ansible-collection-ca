# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: MIT
"""CA collection filter plugins."""

from __future__ import annotations

from typing import Any

from ansible.errors import (
    AnsibleFilterError,
)
from ansible_collections.jomrr.ca.plugins.module_utils._validation import authority_map


def map_authorities(authorities: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return authorities keyed by name and validate the public list shape."""
    try:
        return authority_map(authorities)
    except ValueError as exc:
        raise AnsibleFilterError(str(exc)) from exc


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Any]:
        """Return the filters exported by this plugin."""
        return {
            "authority_map": map_authorities,
        }
