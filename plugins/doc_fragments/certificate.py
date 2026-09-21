# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared certificate dispatch arguments and X.509 return values."""

from dataclasses import dataclass
from typing import ClassVar


@dataclass
class ModuleDocFragment:
    """Ansible documentation fragments."""

    DOCUMENTATION: ClassVar[str] = r"""
options:
  certificate_types:
    description: Role type map. The selected type must define C(issuer) and may define
      C(required_fields).
    version_added: 0.1.0
    type: dict
    required: true
  authorities:
    description: Authority list used to resolve issuer passphrase and C(default_days).
    version_added: 0.1.0
    type: list
    required: true
    elements: dict
  kerberos_realm:
    description: Default realm for MSKDC certificates.
    version_added: 0.1.0
    type: str
    default: ''
"""

    RETURN: ClassVar[str] = r"""
key_changed:
  description: Whether the private key changed.
  type: bool
  returned: success
csr_changed:
  description: Whether the CSR changed.
  type: bool
  returned: success
cert_changed:
  description: Whether the PEM certificate changed.
  type: bool
  returned: success
der_changed:
  description: Whether the DER export changed.
  type: bool
  returned: success
txt_changed:
  description: Whether the text export changed.
  type: bool
  returned: success
archive_changed:
  description: Whether replaced generation material was archived.
  type: bool
  returned: success
inventory_changed:
  description: Whether CA inventory state changed.
  type: bool
  returned: success
renewal:
  description: Renewal decision for this run.
  type: dict
  returned: success
csr_path:
  description: CSR path.
  type: str
  returned: success
cert_path:
  description: PEM certificate path.
  type: str
  returned: success
txt_path:
  description: Text export path, or empty string.
  type: str
  returned: success
formats:
  description: Normalized certificate formats.
  type: list
  returned: success
  elements: str
"""
