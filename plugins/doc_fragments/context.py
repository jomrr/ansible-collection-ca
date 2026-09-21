# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: MIT
"""Shared CA file context documentation."""


class ModuleDocFragment:
    """Ansible documentation fragment."""

    DOCUMENTATION = r"""
options:
  base_dir:
    description: Base directory containing the CA keys, certificates and persistent
      inventory.
    type: path
    required: true
    version_added: 0.1.0
  force:
    description: Regenerate managed artifacts even when current content matches.
    type: bool
    default: false
    version_added: 0.1.0
"""
