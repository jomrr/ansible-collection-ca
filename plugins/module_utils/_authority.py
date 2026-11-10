# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared authority defaults, issuance and inventory operations."""

from __future__ import annotations

from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_results import (
    CertificateResult,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory import (
    update_authority_inventory,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509 import (
    ensure_x509_operation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_params import (
    with_derived_paths,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_preview import preview_x509
from ansible_collections.jomrr.ca.plugins.module_utils._x509_state import SignerMaterial
from ansible_collections.jomrr.ca.plugins.module_utils._x509_validation import (
    prepare_signing_request,
)

ROOT_CA_DEFAULTS = {
    "basic_constraints": ["CA:TRUE", "pathlen:1"],
    "key_usage": ["keyCertSign", "cRLSign"],
    "digest": "sha384",
}
ISSUING_CA_DEFAULTS = {
    "basic_constraints": ["CA:TRUE", "pathlen:0"],
    "key_usage": ["keyCertSign", "cRLSign"],
    "digest": "sha384",
}


def _apply_authority_defaults(
    params: dict[str, Any], defaults: dict[str, Any]
) -> dict[str, Any]:
    """Apply authority defaults without overriding explicit module values."""
    result = dict(params)
    for key, value in defaults.items():
        if result.get(key) in (None, "", []):
            result[key] = list(value) if isinstance(value, list) else value
    return result


def authority_params(params: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Return normalized authority parameters and whether it is parent-signed."""
    result = dict(params)
    name = str(result["name"]).strip()
    parent = str(result.get("parent") or name).strip()
    if not name:
        raise ValueError("Authority name must not be empty")
    if not parent:
        parent = name

    signed = parent != name
    defaults = ISSUING_CA_DEFAULTS if signed else ROOT_CA_DEFAULTS
    result = _apply_authority_defaults(result, defaults)
    result["name"] = name
    result["parent"] = parent

    if signed:
        parent_key_passphrase = result.get("parent_key_passphrase")
        if not parent_key_passphrase:
            raise ValueError("Parent-signed authorities require parent_key_passphrase")
        result["signer_key_passphrase"] = parent_key_passphrase

    return result, signed


def ensure_authority(
    values: dict[str, Any],
    *,
    held_locks: frozenset[str] = frozenset(),
    check_mode: bool = False,
    issuer_pending: bool = False,
    signer: SignerMaterial | None = None,
) -> CertificateResult:
    """Issue one authority and update its inventory, reusing caller-owned locks."""
    params, signed = authority_params(values)
    operation = with_derived_paths(
        params,
        signed=signed,
        authority=True,
        manage_directory=False,
        manage_chain=False,
    )
    operation.check_mode = check_mode
    result = (
        preview_x509(
            operation,
            signed=signed,
            request=prepare_signing_request(
                operation, signer, issuer_pending=issuer_pending
            ),
        )
        if check_mode
        else ensure_x509_operation(operation, held_locks=held_locks, signer=signer)
    )
    inventory_changed = result.get(
        "material_pending", False
    ) or update_authority_inventory(params, result, check_mode=check_mode)
    result["inventory_changed"] = inventory_changed
    result["changed"] = result["changed"] or inventory_changed
    return result
