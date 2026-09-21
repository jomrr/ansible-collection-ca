# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""CA collection filter plugins."""

from __future__ import annotations

from typing import Any

from ansible.errors import (
    AnsibleFilterError,
)
from ansible.plugins import AnsiblePlugin
from ansible_collections.jomrr.ca.plugins.module_utils._validation import authority_map

DOCUMENTATION = r"""
name: authority_map
short_description: Index and validate certificate authorities by name
version_added: 0.1.0
description:
- Validate unique authority names and parent references, then index authorities by name.
- Does not mutate the input list or its dictionaries.
author:
- Jonas Mauer (@jomrr)
options:
  _input:
    description: Authority dictionaries containing name and parent; null produces an empty
      mapping.
    type: list
    elements: dict
    required: true
"""

EXAMPLES = r"""
authority_by_name: "{{ authorities | jomrr.ca.authority_map }}"
"""

RETURN = r"""
_value:
  description: Authority dictionaries keyed by their unique name.
  type: dict
"""


def map_authorities(authorities: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return authorities keyed by name and validate the public list shape."""
    try:
        return authority_map(authorities)
    except (ValueError, TypeError) as exc:
        raise AnsibleFilterError(str(exc)) from exc


class FilterModule(AnsiblePlugin):
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Any]:
        """Return the filters exported by this plugin."""
        return {
            "authority_map": map_authorities,
        }
