# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Map authority definitions to the shared per-authority CRL operation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypedDict

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_args import (
    authority_list_argument,
    authority_options,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl_dispatch import (
    crl_argument_spec,
    ensure_authority_crls,
    validate_crl_policy,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl_models import CrlResult
from ansible_collections.jomrr.ca.plugins.module_utils._input import (
    InputValues,
    mapping,
)
from ansible_collections.jomrr.ca.plugins.module_utils._validation import safe_name

CONTEXT_FIELDS = ("base_dir", "base_url", "ca_name", "owner", "group", "force")


class AuthorityCrlResult(CrlResult):
    """One authority's public CRL result, identified by name."""

    name: str


class CrlBatchResult(TypedDict):
    """Aggregate changes and individual results in input order."""

    changed: bool
    inventory_changed: bool
    count: int
    results: list[AuthorityCrlResult]


def crl_batch_argument_spec() -> dict[str, Any]:
    """Accept the full authority list while declaring all nested credentials."""
    single = crl_argument_spec()
    spec = {key: single[key] for key in (*CONTEXT_FIELDS, "renew_before_days")}
    options = authority_options()
    options["crl_days"] = single["next_update_days"]
    options["crl_digest"] = {
        key: value for key, value in single["digest"].items() if key != "default"
    }
    spec["authorities"] = authority_list_argument(options)
    spec["revocations"] = {"type": "dict", "default": {}}
    return spec


def prepare_crls(params: dict[str, Any]) -> list[dict[str, Any]]:
    """Resolve the role's CRL overrides and validate the batch before writes."""
    defaults = {
        key: option.get("default") for key, option in crl_argument_spec().items()
    }
    revocations = InputValues(InputValues(params).dictionary("revocations"))
    prepared = []
    names: set[str] = set()
    for authority in params["authorities"]:
        name = safe_name(authority["name"], "Authority")
        if name in names:
            raise ValueError(f"Duplicate authority name {name}")
        names.add(name)
        values = {
            **defaults,
            **{key: params[key] for key in CONTEXT_FIELDS},
            "name": name,
            "key_passphrase": authority["key_passphrase"],
            "next_update_days": authority["crl_days"],
            "renew_before_days": params["renew_before_days"],
            "revoked_certificates": [
                mapping(entry, f"Revocation for {name}")
                for entry in revocations.sequence(name)
            ],
        }
        for source, target in (
            ("crl_renew_before_days", "renew_before_days"),
            ("crl_digest", "digest"),
            ("archived_key_passphrases", "archived_key_passphrases"),
            ("legacy_generation", "legacy_generation"),
        ):
            if authority.get(source) is not None:
                values[target] = authority[source]
        validate_crl_policy(values)
        prepared.append(values)
    return prepared


def ensure_crl_batch(
    params: dict[str, Any], *, warn: Callable[[str], None], check_mode: bool = False
) -> CrlBatchResult:
    """Run independent CRL operations, releasing each authority's locks in turn."""
    results: list[AuthorityCrlResult] = []
    for values in prepare_crls(params):
        result = ensure_authority_crls(values, warn=warn, check_mode=check_mode)
        results.append({"name": values["name"], **result})
    return CrlBatchResult(
        changed=any(result["changed"] for result in results),
        inventory_changed=any(result["inventory_changed"] for result in results),
        count=len(results),
        results=results,
    )
