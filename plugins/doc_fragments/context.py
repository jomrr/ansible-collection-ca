# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared CA file context documentation."""

from dataclasses import dataclass
from typing import ClassVar


@dataclass
class ModuleDocFragment:
    """Ansible documentation fragment."""

    DOCUMENTATION: ClassVar[str] = r"""
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
