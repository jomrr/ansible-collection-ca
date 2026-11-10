# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Manage CRLs for multiple authorities in one managed-host invocation."""

from __future__ import annotations

DOCUMENTATION = r"""
module: crl_batch
short_description: Manage authority CRLs in one batch
version_added: 1.2.0
description:
- Renew CRLs for existing authorities in input order using the same generation,
  revocation and inventory implementation as M(jomrr.ca.crl).
- Authority and CRL locks are acquired and released separately for each authority.
- Authority certificates and chains are not created or renewed by this module.
notes:
- Each authority requires C(name), C(key_passphrase) and C(crl_days).
  C(crl_renew_before_days) overrides O(renew_before_days); C(crl_digest) defaults
  to C(sha384). CRLs use PEM and DER formats and file mode C(0644).
- C(archived_key_passphrases) and C(legacy_generation) retain the single-module
  semantics. All active CA generations are managed, including retained issuers.
- Empty batches return unchanged. Duplicate names and invalid renewal windows
  fail before writes. An operational failure stops the batch; earlier authorities
  may already have been updated and are reconciled on the next run.
- This is independent of M(jomrr.ca.authority_batch), allowing CRL-only task tags.
extends_documentation_fragment: [jomrr.ca.context, jomrr.ca.context.ownership,
  jomrr.ca.context.publishing, jomrr.ca.context.cryptography, jomrr.ca.crl_batch]
options:
  revocations:
    description:
    - Revocations keyed by authority name. Missing entries mean an empty list.
    - Each value is a list of selectors accepted by O(jomrr.ca.crl#module:revoked_certificates),
      including names, fingerprints, serials, reasons and dates.
    - Persisted revocations remain effective when declarations are removed.
      Entries for authorities outside this batch are not processed.
    type: dict
    default: {}
  renew_before_days:
    description: Shared renewal window in days; must be nonnegative and less
      than each authority's C(crl_days) unless overridden for that authority.
    type: float
    default: 7
  base_url:
    description: Stored in composed inventory when C(ca_name) is set.
"""

EXAMPLES = r"""
- name: Refresh CA revocation lists independently of authority issuance
  jomrr.ca.crl_batch:
    base_dir: /srv/pki/example
    authorities: "{{ ca_authorities }}"
    revocations: "{{ ca_revocations }}"
    renew_before_days: "{{ ca_crl_renew_before_days }}"
    ca_name: example
    owner: root
    group: root
  no_log: true
  tags: ca_crl
"""

RETURN = r"""
count:
  description: Number of processed authorities.
  type: int
  returned: success
inventory_changed:
  description: Whether any authority's CRL inventory changed.
  type: bool
  returned: success
results:
  description:
  - Results in authority input order, each containing C(name) and the full result
    of M(jomrr.ca.crl), including C(changed), C(inventory_changed), C(paths),
    C(formats), C(crl_number), C(generations), C(legacy_generation) and
    C(migration_conflicts). No credentials are included.
  type: list
  elements: dict
  returned: success
"""

# Ansible requires DOCUMENTATION, EXAMPLES and RETURN before normal imports.
# pylint: disable=wrong-import-position
from collections.abc import Callable
from functools import partial
from typing import cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._crl_batch import (
    crl_batch_argument_spec,
    ensure_crl_batch,
)
from ansible_collections.jomrr.ca.plugins.module_utils._module import (
    execute_certificate,
)

# pylint: enable=wrong-import-position


def main() -> None:
    """Run CRL reconciliation through the shared Ansible lifecycle."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec=crl_batch_argument_spec(), supports_check_mode=False
    )
    execute_certificate(module, partial(ensure_crl_batch, warn=module.warn))


if __name__ == "__main__":
    main()
