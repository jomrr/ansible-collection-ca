# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Document full authority definitions with CRL-specific field meanings."""

from dataclasses import dataclass
from typing import ClassVar

import yaml
from ansible_collections.jomrr.ca.plugins.doc_fragments.certificate_definition import (
    ModuleDocFragment as CertificateDefinition,
)
from ansible_collections.jomrr.ca.plugins.doc_fragments.certificate_definition import (
    authority_list_documentation,
)


def _crl_authorities() -> str:
    fields = yaml.safe_load(CertificateDefinition.AUTHORITIES)["options"][
        "authorities"
    ]["suboptions"]
    descriptions = {
        "name": "Existing authority whose CRLs are managed.",
        "key_passphrase": (
            "Current CA key password; also the fallback for archived keys. "
            "Protected by Ansible C(no_log)."
        ),
        "crl_days": "Number of days until CRL nextUpdate; required and positive.",
        "crl_renew_before_days": (
            "Authority renewal window; overrides O(renew_before_days), including zero."
        ),
        "crl_digest": "CRL signature digest for RSA and ECDSA; defaults to sha384.",
        "archived_key_passphrases": (
            "Generation IDs mapped to archived key passwords. Ansible masks "
            "the entire mapping, including keys."
        ),
        "legacy_generation": (
            "Optional generation ID owning the unsuffixed publication paths "
            "during migration."
        ),
    }
    for name, description in descriptions.items():
        fields[name]["description"] = description
    fields["crl_days"]["required"] = True
    fields["crl_digest"]["choices"] = ["sha224", "sha256", "sha384", "sha512"]
    return authority_list_documentation(
        fields,
        "Authority definitions. Only CRL fields and credentials are used; "
        "other fields are accepted as metadata.",
    )


@dataclass
class ModuleDocFragment:
    """Nested authority input for the CRL batch module."""

    DOCUMENTATION: ClassVar[str] = _crl_authorities()
