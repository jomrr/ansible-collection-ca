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
notes:
- Passphrase and other secret fields inside the certificate and authority dictionaries
  are masked in Ansible output, including validation failures. Non-secret names,
  formats, issuer groups and returned paths remain usable in registered results.
- Ansible masks matching secret values throughout output. A public value identical
  to or containing an actual passphrase is therefore still redacted. Task-level
  C(no_log=true) remains available when the complete certificate metadata is confidential.
- AIA/CDP URLs identify the actual signing CA generation. The original issuer keeps
  its unsuffixed filenames; after CA rekey, new certificates reference filenames
  containing the new generation ID. Publish every retained generation with
  M(jomrr.ca.publish_archive) using C(authorities), and refresh CRLs with M(jomrr.ca.crl).
- Reusing a public key from a locally recorded certificate revoked with C(key_compromise)
  or C(ca_compromise) fails, including renewal, batch issuance and external CSRs.
  The check spans recorded generations and certificate names in the same C(base_dir).
- C(renewal.rekey) defaults to C(false). For a compromised managed key, request
  C(renewal.rekey=true) when renewal is due or C(force=true) to generate a new key.
  An external CSR must contain a new key; C(force) cannot bypass the check.
- Other revocation reasons do not automatically prohibit key reuse. Revocation data
  must already have been recorded by M(jomrr.ca.crl); external CRLs are not imported.
- External CSRs supply only the public key. The CSR signature is verified; requested
  subject attributes and SANs are not copied into the certificate.
- CSR signing requires C(certificate.common_name) or C(certificate.subject_ordered).
  A configured C(common_name) must match the CSR common name. The issued subject is
  built from task parameters, including merged C(subject) defaults or C(subject_ordered).
- SANs come from C(certificate.san) and profile defaults, even when C(san) is omitted
  or empty. Approved UPNs, DNS names and other identities must be supplied by the task.
  Existing CSR tasks relying on implicit identities must specify them explicitly.
- Issuance checks the complete managed issuer chain for Basic Constraints,
  certificate-signing Key Usage and path length limits before writing certificate material.
- Use C(type=issuing_ca) (added in version 1.1.0) to sign an external issuing CA CSR
  supplied through C(csr_path) on the managed CA host or inline PEM C(csr_content).
  Set C(certificate_types.issuing_ca.issuer) to the managed root name and supply
  its C(key_passphrase) in C(authorities). The external private key stays external.
- The C(issuing_ca) profile defaults to C(basic_constraints=[CA:TRUE, pathlen:0])
  and C(key_usage=[keyCertSign, cRLSign]), with no EKU or SAN defaults.
  It exports C(pem), C(der), C(txt) and C(fullchain). Explicit extension overrides
  remain available; CSR extensions never select these values.
- A root can sign a CA request when its path length permits the additional CA level.
  Other profiles can still request a CA using explicit C(basic_constraints) and C(key_usage).
- The signed external CA is inventoried as a certificate, not installed as a managed
  authority. Import C(cert_path) or C(fullchain_path) into the external CA separately;
  that system manages its own leaf certificates and CRLs.
- The selected issuer comes from C(certificate_types[type].issuer). A CA with C(pathlen:0)
  cannot sign another non-self-issued CA usable for leaf issuance. A larger or absent
  child path length does not override limits inherited from ancestors.
options:
  certificate_types:
    description: Role type map. The selected type must define C(issuer) and may define
      C(required_fields).
    version_added: 0.1.0
    type: dict
    required: true
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
