# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Prepare and execute a parent-first authority graph in one module operation."""

from __future__ import annotations

from collections import defaultdict
from graphlib import CycleError, TopologicalSorter
from typing import Any, TypedDict

from ansible_collections.jomrr.ca.plugins.module_utils._authority import (
    ensure_authority,
)
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_args import (
    authority_list_argument,
    authority_options,
)
from ansible_collections.jomrr.ca.plugins.module_utils._chain import (
    authority_lock_paths,
    ensure_authority_chain,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    ca_lock_path,
    file_locks,
)
from ansible_collections.jomrr.ca.plugins.module_utils._validation import (
    authority_map,
    require_value,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_params import (
    ca_authority_argument_spec,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_state import SignerMaterial


class AuthorityResult(TypedDict):
    """Non-secret per-authority batch results."""

    name: str
    changed: bool
    cert_path: str
    csr_path: str
    chain_paths: dict[str, str]
    chain_changed: bool
    inventory_changed: bool


class AuthorityBatchResult(TypedDict):
    """Aggregate change state and parent-first results."""

    changed: bool
    inventory_changed: bool
    count: int
    results: list[AuthorityResult]


def authority_batch_argument_spec() -> dict[str, Any]:
    """Reuse authority field validation and nested secret declarations."""
    single = ca_authority_argument_spec()
    spec = {
        key: single[key]
        for key in (
            "base_dir",
            "base_url",
            "ca_name",
            "subject",
            "renewal",
            "force",
            "owner",
            "group",
        )
    }
    options = authority_options()
    for key in ("parent", "days"):
        options[key]["required"] = True
    spec["authorities"] = authority_list_argument(options)
    return spec


def prepare_authorities(params: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate the whole graph, then merge context and resolve parent credentials."""
    authorities = authority_map(params["authorities"])
    parents = {name: str(item["parent"]).strip() for name, item in authorities.items()}
    graph = {
        name: [] if parent == name else [parent] for name, parent in parents.items()
    }
    try:
        order = tuple(TopologicalSorter(graph).static_order())
    except CycleError as exc:
        raise ValueError("Authority graph contains a cycle") from exc
    for name, item in authorities.items():
        require_value(item, "key_passphrase", f"Authority {name}")
    defaults = {
        key: option.get("default")
        for key, option in ca_authority_argument_spec().items()
    }
    context = {
        key: params[key]
        for key in ("base_dir", "base_url", "ca_name", "force", "owner", "group")
    }
    prepared = []
    for name in order:
        item = authorities[name]
        values = {
            **defaults,
            **{
                key: value
                for key, value in item.items()
                if key in defaults and value is not None
            },
            **context,
            "name": name,
            "parent": parents[name],
            "parent_key_passphrase": authorities[parents[name]]["key_passphrase"],
            "subject": {**params["subject"], **(item.get("subject") or {})},
            "renewal": {**params["renewal"], **(item.get("renewal") or {})},
        }
        prepared.append(values)
    return prepared


def ensure_authority_batch(
    params: dict[str, Any], *, check_mode: bool = False
) -> AuthorityBatchResult:
    """Run authority, inventory and chain operations under one graph lock."""
    prepared = prepare_authorities(params)
    results: list[AuthorityResult] = []
    identities: set[str] = set()
    pending_chains: set[str] = set()
    signers: dict[str, SignerMaterial] = defaultdict(SignerMaterial)
    if prepared:
        base_dir = params["base_dir"]
        locks = frozenset(
            [
                ca_lock_path(base_dir, "authority", "__graph__"),
                *authority_lock_paths(base_dir, (item["name"] for item in prepared)),
            ]
        )
        with file_locks(locks, readonly=check_mode):
            for item in prepared:
                material = ensure_authority(
                    item,
                    held_locks=locks,
                    check_mode=check_mode,
                    issuer_pending=item["parent"] in identities,
                    signer=signers[item["parent"]],
                )
                if material.get("identity_changed"):
                    identities.add(item["name"])
                if material.get("material_pending") or item["parent"] in pending_chains:
                    pending_chains.add(item["name"])
                chain = ensure_authority_chain(
                    {**item, "formats": ["pem", "der", "txt"], "mode": "0644"},
                    held_locks=locks,
                    check_mode=check_mode,
                    material_pending=item["name"] in pending_chains,
                )
                results.append(
                    AuthorityResult(
                        name=item["name"],
                        changed=material["changed"] or chain["changed"],
                        cert_path=material["cert_path"],
                        csr_path=material["csr_path"],
                        chain_paths=chain["paths"],
                        chain_changed=chain["changed"],
                        inventory_changed=material["inventory_changed"],
                    )
                )
    return AuthorityBatchResult(
        changed=any(item["changed"] for item in results),
        inventory_changed=any(item["inventory_changed"] for item in results),
        count=len(results),
        results=results,
    )
