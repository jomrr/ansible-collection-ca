# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared CA execution and file context documentation."""

from dataclasses import dataclass
from typing import ClassVar


@dataclass
class ModuleDocFragment:
    """Ansible documentation fragments."""

    DOCUMENTATION: ClassVar[str] = r"""
author: [Jonas Mauer (@jomrr)]
attributes:
  check_mode:
    support: none
    description: Skipped in check mode without changing the managed host.
  diff_mode:
    support: none
    description: No diff output is returned.
requirements:
- Python 3.12 on the managed Linux host
notes:
- The base directory and persistent inventory must be preserved between runs.
- Private utilities are internal implementation details and are not a public API.
options:
  base_dir:
    description: Base directory containing the CA keys, certificates and persistent inventory.
    type: path
    required: true
    version_added: 0.1.0
  force:
    description: Regenerate managed artifacts even when current content matches.
    type: bool
    default: false
    version_added: 0.1.0
"""

    CRYPTOGRAPHY: ClassVar[str] = r"""
requirements:
- cryptography >= 43 on the managed host
options: {}
"""

    OWNERSHIP: ClassVar[str] = r"""
options:
  owner:
    description: Owner of generated files; user name or numeric UID.
    type: str
    version_added: 0.1.0
  group:
    description: Group of generated files; group name or numeric GID.
    type: str
    version_added: 0.1.0
"""

    PUBLISHING: ClassVar[str] = r"""
options:
  base_url:
    description: Base publication URL. If set, AIA defaults to C(<base_url>/aia/<parent>-ca.der)
      and CDP to C(<base_url>/crl/<parent>-ca.crl); a root references itself.
    version_added: 0.1.0
    type: str
    default: ''
  ca_name:
    description: Enables composed inventory output when non-empty.
    version_added: 0.1.0
    type: str
    default: ''
"""

    DIGEST: ClassVar[str] = r"""
options:
  digest:
    description: Signature digest for RSA and ECDSA keys.
    version_added: 0.1.0
    type: str
    default: sha384
    choices: [sha224, sha256, sha384, sha512]
"""

    FORMATS: ClassVar[str] = r"""
options:
  formats:
    description: Output formats for the CA certificate.
    version_added: 0.1.0
    type: list
    default: [pem, der, txt]
    elements: str
"""

    FILE_MODE: ClassVar[str] = r"""
options:
  mode:
    description: Chain file mode.
    version_added: 0.1.0
    type: str
    default: '0644'
"""

    DISPATCH_NOTES: ClassVar[str] = r"""
notes:
- Supply the authorities and certificate_types mappings explicitly; no standalone role
  defaults are loaded.
- Pass owner and group explicitly; the source implementation needs these values when deriving
  certificate paths.
options: {}
"""

    FRITZBOX_NOTES: ClassVar[str] = r"""
notes:
- TLS verification defaults to false for self-signed FRITZ!Box device certificates. Enable
  validate_certs when the device certificate is trusted.
options: {}
"""
