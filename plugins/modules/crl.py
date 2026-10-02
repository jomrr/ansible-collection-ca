# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Manage CA collection certificate revocation lists."""

from __future__ import annotations

DOCUMENTATION = r"""
module: crl
short_description: Manage CA collection certificate revocation lists
version_added: 0.1.0
description:
- Manage CA collection certificate revocation lists.
- The CRL issuer is the complete subject of the loaded CA certificate, including
  email addresses and ordered subject attributes. Existing CRLs with a different
  issuer are replaced with the next CRL number.
- After CA rekey, renew CRLs for every active issuer generation with its matching
  current or archived private key. All carry the authority's complete revocation list,
  a shared monotonic CRL number and C(thisUpdate). Old CRLs cap C(nextUpdate) at retirement.
- The original generation keeps C(<name>-ca.crl); subsequent generations use
  C(<name>-ca-<generation_id>.crl). PEM exports append C(.pem).
- Old generations retire when their last recorded issued certificate expires,
  bounded by CA expiry. Without complete attribution, CA expiry is the fallback.
  Managed subordinate CAs and externally requested CA certificates count too.
- Retired generations are no longer signed or decrypted. Their last CRL and public
  certificates are retained; the operator may destroy their archived private keys.
  No key is deleted automatically. Preserve generation and inventory state.
- A missing or unreadable active generation key fails preparation before writing
  CRLs or revocation state. Final CRL nextUpdate is capped at the retirement deadline.
- Earlier rollovers are reconstructed from archived CA certificates and keys.
  If existing certificates conflict on legacy URLs, select O(legacy_generation).
  RV(migration_conflicts) identifies certificates to reissue or revoke; rewriting
  publication files cannot change their embedded URLs.
extends_documentation_fragment: [jomrr.ca.context, jomrr.ca.context.ownership, jomrr.ca.context.publishing,
  jomrr.ca.context.digest, jomrr.ca.context.formats, jomrr.ca.context.file_mode, jomrr.ca.context.cryptography]
options:
  name:
    description: Authority short name used to locate its certificate and private key.
    version_added: 0.1.0
    type: str
    required: true
  key_passphrase:
    description: Passphrase for the CA private key.
    version_added: 0.1.0
    type: str
    required: true
  archived_key_passphrases:
    description:
    - Optional mapping of generation IDs to archived private-key passphrases.
    - Defaults to O(key_passphrase) for IDs without an override. IDs are returned
      in RV(generations) and stored below C(generations/<name>/) on the CA host.
    version_added: 1.1.0
    type: dict
    default: {}
  legacy_generation:
    description:
    - Optional generation ID to own the unsuffixed AIA/CDP filenames during migration.
    - Automatically inferred from historical certificate URLs or an unambiguous
      oldest CA certificate. Ambiguous selection fails and lists IDs and serials.
    - Once recorded, this owner cannot be changed through this option.
    version_added: 1.1.0
    type: str
    default: ''
  common_name:
    description: Accepted for compatibility; the issuer Common Name comes from the CA certificate.
    version_added: 0.1.0
    type: str
    required: true
  subject:
    description: Accepted for compatibility; the complete issuer subject comes from the CA certificate.
    version_added: 0.1.0
    type: dict
    default: {}
  next_update_days:
    description: Number of days until CRL C(nextUpdate).
    version_added: 0.1.0
    type: int
    required: true
  renew_before_days:
    description: Renew this many days before CRL expiry; must be less than next_update_days.
    version_added: 0.1.0
    type: float
    default: 7
  revoked_certificates:
    description: Declarative revoked certificate entries.
    version_added: 0.1.0
    type: list
    default: []
    elements: dict
  base_url:
    description: Stored in composed inventory when C(ca_name) is set.
  digest:
    description: Signature digest for RSA and ECDSA CA keys.
  formats:
    description: Output formats written from one CRL object per issuer generation.
    default: [pem, der]
  mode:
    description: CRL file mode.
"""

EXAMPLES = r"""
- name: Create component CA CRL
  jomrr.ca.crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    common_name: Example Component CA
    subject: {country: DE, organization: Example, organizational_unit: Example PKI}
    next_update_days: 7
    renew_before_days: 1
    key_passphrase: "{{ ca_component_passphrase }}"

- name: Create component CA CRLs
  jomrr.ca.crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    common_name: Example Component CA
    next_update_days: 7
    renew_before_days: 1
    key_passphrase: "{{ ca_component_passphrase }}"
    revoked_certificates:
      - name: web01
        reason: key_compromise
        invalidity_date: "2026-06-14T00:00:00Z"

- name: Create component CA CRLs with fingerprint revocation
  jomrr.ca.crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    common_name: Example Component CA
    next_update_days: 7
    renew_before_days: 1
    key_passphrase: "{{ ca_component_passphrase }}"
    revoked_certificates:
      - sha256: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        reason: superseded
"""

RETURN = r"""
inventory_changed:
  description: Whether inventory state changed.
  type: bool
  returned: success
paths:
  description: Current CA generation output paths keyed by format.
  type: dict
  returned: success
crl_number:
  description: CRL Number extension value.
  type: int
  returned: success
generations:
  description: Mapping of issuer generation IDs to C(paths), C(retire_at) and
    C(retired). Active generations also include C(crl_number). The current CA
    remains active while it is the configured signer.
  type: dict
  returned: success
  version_added: 1.1.0
legacy_generation:
  description: Generation ID pinned to the unsuffixed AIA/CDP filenames.
  type: str
  returned: success
  version_added: 1.1.0
migration_conflicts:
  description: Unexpired, unrevoked certificates whose legacy URLs conflict with
    the pinned owner, including C(name), C(serial_number) and C(generation_id).
    An unknown issuer generation is returned as C(null).
  type: list
  elements: dict
  returned: success
  version_added: 1.1.0
formats:
  description: Normalized CRL output formats.
  type: list
  elements: str
  returned: success
"""

# Ansible requires DOCUMENTATION, EXAMPLES and RETURN before normal imports.
# pylint: disable=wrong-import-position
from collections.abc import Callable
from typing import Any, cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._crl_engine import ensure_crls
from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    OPERATION_ERRORS,
    require_cryptography,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    ca_lock_path,
    file_argument_spec,
    file_locks,
    sanitize_error,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import DIGESTS

# pylint: enable=wrong-import-position


def main() -> None:
    """Run the Ansible module for certificate revocation lists."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "base_url": {"type": "str", "default": ""},
            "ca_name": {"type": "str", "default": ""},
            "name": {"type": "str", "required": True},
            "formats": {
                "type": "list",
                "elements": "str",
                "default": ["pem", "der"],
            },
            "key_passphrase": {"type": "str", "required": True, "no_log": True},
            "archived_key_passphrases": {"type": "dict", "default": {}, "no_log": True},
            "legacy_generation": {"type": "str", "default": ""},
            "common_name": {"type": "str", "required": True},
            "subject": {"type": "dict", "default": {}},
            "next_update_days": {"type": "int", "required": True},
            "renew_before_days": {"type": "float", "default": 7},
            "revoked_certificates": {"type": "list", "elements": "dict", "default": []},
            "digest": {"type": "str", "default": "sha384", "choices": list(DIGESTS)},
            **file_argument_spec(),
        },
        supports_check_mode=False,
    )

    require_cryptography(module)

    params: dict[str, Any] = module.params
    try:
        if not 0 <= params["renew_before_days"] < params["next_update_days"]:
            raise ValueError(
                "renew_before_days must be nonnegative and less than next_update_days"
            )
        with file_locks(
            [
                ca_lock_path(params["base_dir"], "authority", params["name"]),
                ca_lock_path(params["base_dir"], "crl", params["name"]),
            ]
        ):
            result = ensure_crls(params)
    except OPERATION_ERRORS as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))
    if result["migration_conflicts"]:
        module.warn(
            "Some certificates reference legacy URLs assigned to another generation; "
            "reissue or revoke those listed in migration_conflicts"
        )
    module.exit_json(**result)


if __name__ == "__main__":
    main()
