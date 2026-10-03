# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

Renew CRLs with a shared monotonic sequence for every retained CA signing generation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._authority_generations import (
    generation_key,
    generation_root,
    generation_stem,
    legacy_id,
    store_generations,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl import (
    build_crl,
    desired_revoked,
    existing_numbers,
    load_existing_crls,
    needs_rebuild,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl_models import (
    CrlPlan,
    CrlRequest,
    GenerationResult,
    GenerationStatus,
    revocation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl_state import (
    last_crl_number,
    store_crl_number,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._generation_history import (
    ca_history,
    generation_id,
    issued_history,
    legacy_references,
    retirement_times,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory import (
    update_crl_inventory,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_revocation import (
    resolve_revocation_entries,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_store import (
    write_json,
)
from ansible_collections.jomrr.ca.plugins.module_utils._paths import (
    crl_paths,
)
from ansible_collections.jomrr.ca.plugins.module_utils._time import (
    now_utc,
    parse_datetime,
    timestamp_z,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import PrivateKey
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass


SUPPORTED_FORMATS = {"pem", "der"}


def _write_crls(params: CrlPlan, crl: x509.CertificateRevocationList) -> bool:
    """Write one CRL object to all requested output formats."""
    changed = False
    for crl_format, path in params.paths.items():
        encoding = (
            serialization.Encoding.DER
            if crl_format == "der"
            else serialization.Encoding.PEM
        )
        changed = (
            write_file(
                path,
                crl.public_bytes(encoding),
                params.request.context.attributes,
                force=params.request.policy.force,
            )
            or changed
        )
    return changed


@dataclass
class CrlGeneration:
    """A validated signing generation and its existing publication state."""

    params: CrlPlan
    cert: x509.Certificate
    key: PrivateKey
    existing: x509.CertificateRevocationList | None
    changed: bool


def _generation_params(
    params: CrlRequest, identity: str, stop_at: datetime | None = None
) -> CrlPlan:
    """Derive publication paths without loading a potentially retired key."""
    stem = generation_stem(params.context.name, identity, params.legacy_generation)
    return CrlPlan(
        params,
        identity,
        identity if stem != f"{params.context.name}-ca" else "",
        crl_paths(params.context.base_dir, stem, params.formats),
        stop_at,
    )


def _prepare_crl(
    params: CrlPlan,
    cert: x509.Certificate,
    previous_number: int,
    key_paths: list[str],
) -> CrlGeneration:
    """Validate sequence state and every required key before making any writes."""
    existing_crls = load_existing_crls(params.paths)
    numbers = existing_numbers(existing_crls)
    if not previous_number and any(
        Path(path).exists() for path in params.paths.values()
    ):
        raise ValueError("CRL exports exist but their sequence state is missing")
    if any(number > previous_number for number in numbers):
        raise ValueError("CRL export number exceeds the persistent sequence")
    changed = (
        params.request.policy.force
        or previous_number > max(numbers or [0])
        or needs_rebuild(
            existing_crls=existing_crls,
            params=params,
            ca_cert=cert,
            expected_revoked=desired_revoked(params.request.revoked_certificates),
        )
    )
    return CrlGeneration(
        params,
        cert,
        generation_key(
            params.request.context.name,
            params.identity,
            cert,
            params.request.credentials,
            key_paths,
        ),
        next((crl for crl in existing_crls.values() if crl is not None), None),
        changed,
    )


def _build_crls(
    prepared: list[CrlGeneration], number: int, rebuild: bool
) -> list[tuple[CrlPlan, x509.CertificateRevocationList]]:
    """Sign all active generations before committing any exported state."""
    crl_time = now_utc(strip_microseconds=True)
    crls = []
    for item in prepared:
        crl = (
            build_crl(
                item.params,
                now=crl_time,
                crl_number=number,
                ca_cert=item.cert,
                private_key=item.key,
            )
            if rebuild
            else item.existing
        )
        if crl is None:
            raise ValueError("Missing existing CRL")
        crls.append((item.params, crl))
    return crls


def _store_status(
    params: CrlRequest, status: dict[str, GenerationStatus]
) -> tuple[bool, dict[str, GenerationResult]]:
    """Persist retirement deadlines without opening any retired signing keys."""
    changed = False
    generations: dict[str, GenerationResult] = {}
    for identity, state in status.items():
        changed = (
            write_json(
                str(
                    generation_root(params.context.base_dir, params.context.name)
                    / identity
                    / "status.json"
                ),
                state,
                params.context.attributes.owner,
                params.context.attributes.group,
                "0644",
            )
            or changed
        )
        if state["retired"]:
            paths = _generation_params(params, identity).paths
            generations[identity] = {
                "retire_at": state["retire_at"],
                "retired": state["retired"],
                "paths": {
                    key: path for key, path in paths.items() if Path(path).exists()
                },
            }
    return changed, generations


def _store_crls(
    params: CrlRequest,
    issuers: dict[str, x509.Certificate],
    prepared: list[CrlGeneration],
    status: dict[str, GenerationStatus],
) -> dict[str, Any]:
    """Reserve the shared number, then persist status, revocations and CRL exports."""
    rebuild = any(item.changed for item in prepared)
    number = last_crl_number(params.context.base_dir, params.context.name) + int(
        rebuild
    )
    crls = _build_crls(prepared, number, rebuild)
    changed, generations = _store_status(params, status)
    changed = (
        store_generations(
            params.context.base_dir,
            params.context.name,
            issuers,
            params.legacy_generation,
            params.context.attributes,
        )
        or changed
    )
    changed = (
        store_crl_number(
            params.context.base_dir,
            params.context.name,
            number,
            params.context.attributes,
        )
        or changed
        or rebuild
    )
    inventory_changed = False
    for generation_params, crl in crls:
        inventory_changed = (
            update_crl_inventory(generation_params, crl) or inventory_changed
        )
        changed = _write_crls(generation_params, crl) or changed
        identity = generation_params.identity
        generations[identity] = {
            **status[identity],
            "paths": generation_params.paths,
            "crl_number": number,
        }
    return {
        "changed": changed or inventory_changed,
        "inventory_changed": inventory_changed,
        "generations": generations,
        "crl_number": number,
    }


def ensure_crls(values: dict[str, Any]) -> dict[str, Any]:
    """Prepare all CRLs first, then reserve numbers and persist state and exports."""
    params = CrlRequest.from_input(
        values,
        [
            revocation(entry)
            for entry in resolve_revocation_entries(
                base_dir=values["base_dir"],
                authority=values["name"],
                entries=values["revoked_certificates"],
            )
        ],
    )
    history = ca_history(params.context.base_dir, params.context.name)
    current = history.require_current()
    current_id = generation_id(current.subject, current.public_key())
    issuers = history.certificates
    records = issued_history(params.context.base_dir, params.context.name, issuers)
    params.legacy_generation = legacy_id(
        params.context.base_dir,
        params.context.name,
        params.legacy_generation,
        history,
        records,
    )
    deadlines = retirement_times(issuers, records)
    crl_time = now_utc(strip_microseconds=True)
    status: dict[str, GenerationStatus] = {
        identity: {
            "retire_at": timestamp_z(deadlines[identity]),
            "retired": identity != current_id and deadlines[identity] <= crl_time,
        }
        for identity in issuers
    }
    previous_number = last_crl_number(params.context.base_dir, params.context.name)
    prepared = [
        _prepare_crl(
            _generation_params(
                params,
                identity,
                deadlines[identity] if identity != current_id else None,
            ),
            cert,
            previous_number,
            history.key_paths.get(identity, []),
        )
        for identity, cert in issuers.items()
        if not status[identity]["retired"]
    ]
    result = _store_crls(params, issuers, prepared, status)
    revoked = {str(entry["serial_number"]) for entry in params.revoked_certificates}
    conflicts = [
        {
            "name": record["name"],
            "serial_number": record["certificate"]["serial_number"],
            "generation_id": record["issuer_generation"],
        }
        for record in records
        if legacy_references(params.context.name, record)
        and record["issuer_generation"] != params.legacy_generation
        and record["certificate"]["serial_number"] not in revoked
        and (parse_datetime(record["certificate"]["not_valid_after"]) or crl_time)
        > crl_time
    ]
    return {
        **result,
        "formats": params.formats,
        "legacy_generation": params.legacy_generation,
        "migration_conflicts": conflicts,
        "paths": result["generations"][current_id]["paths"],
    }
