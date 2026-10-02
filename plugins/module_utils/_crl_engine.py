# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

Renew CRLs with a shared monotonic sequence for every retained CA signing generation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._authority_generations import (
    _legacy_id,
    generation_id,
    generation_key,
    generation_root,
    generation_stem,
    retain_generation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl import (
    _build_crl,
    _desired_revoked,
    _existing_numbers,
    _load_existing_crls,
    _needs_rebuild,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl_state import (
    last_crl_number,
    store_crl_number,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    FileAttributes,
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._generation_history import (
    ca_history,
    issued_history,
    legacy_references,
    retirement_times,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory import (
    resolve_revocation_entries,
    update_crl_inventory,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_store import (
    _write_json,
)
from ansible_collections.jomrr.ca.plugins.module_utils._time import (
    now_utc,
    parse_datetime,
    timestamp_z,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    load_certificate,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import PrivateKey
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass


SUPPORTED_FORMATS = {"pem", "der"}


def _formats(value: Any) -> list[str]:
    """Return normalized CRL output formats."""
    if isinstance(value, str):
        raise TypeError("formats must be a list")
    formats = [str(item).lower() for item in (value or ["pem", "der"])]
    unsupported = sorted(set(formats).difference(SUPPORTED_FORMATS))
    if unsupported:
        raise ValueError(f"Unsupported CRL formats: {', '.join(unsupported)}")
    return formats


def _write_crls(params: dict[str, Any], crl: x509.CertificateRevocationList) -> bool:
    """Write one CRL object to all requested output formats."""
    changed = False
    for crl_format, path in params["paths"].items():
        encoding = (
            serialization.Encoding.DER
            if crl_format == "der"
            else serialization.Encoding.PEM
        )
        changed = (
            write_file(
                path,
                crl.public_bytes(encoding),
                FileAttributes.from_params(params, "mode"),
                force=params["force"],
            )
            or changed
        )
    return changed


@dataclass
class CrlGeneration:
    """A validated signing generation and its existing publication state."""

    params: dict[str, Any]
    cert: x509.Certificate
    key: PrivateKey
    existing: x509.CertificateRevocationList | None
    changed: bool


def _generation_params(params: dict[str, Any], identity: str) -> dict[str, Any]:
    """Derive public paths without loading a potentially retired private key."""
    params = dict(params)
    stem = generation_stem(
        params["base_dir"],
        params["name"],
        identity,
        params.get("legacy_generation", ""),
    )
    params["generation_id"] = identity
    params["generation_suffix"] = identity if stem != f"{params['name']}-ca" else ""
    params["paths"] = {
        crl_format: f"{params['base_dir']}/crl/{stem}.{suffix}"
        for crl_format, suffix in (("pem", "crl.pem"), ("der", "crl"))
        if crl_format in params["formats"]
    }
    return params


def _prepare_crl(
    params: dict[str, Any], identity: str, cert: x509.Certificate, previous_number: int
) -> CrlGeneration:
    """Validate sequence state and every required key before making any writes."""
    params = dict(params)
    params = _generation_params(params, identity)
    existing_crls = _load_existing_crls(params["paths"])
    existing_numbers = _existing_numbers(existing_crls)
    if not previous_number and any(
        Path(path).exists() for path in params["paths"].values()
    ):
        raise ValueError("CRL exports exist but their sequence state is missing")
    if any(number > previous_number for number in existing_numbers):
        raise ValueError("CRL export number exceeds the persistent sequence")
    changed = (
        params["force"]
        or previous_number > max(existing_numbers or [0])
        or _needs_rebuild(
            existing_crls=existing_crls,
            params=params,
            ca_cert=cert,
            desired_revoked=_desired_revoked(params["revoked_certificates"]),
        )
    )
    return CrlGeneration(
        params,
        cert,
        generation_key(params, identity, cert),
        next((crl for crl in existing_crls.values() if crl is not None), None),
        changed,
    )


def _build_crls(
    prepared: list[CrlGeneration], number: int, rebuild: bool
) -> list[tuple[dict[str, Any], x509.CertificateRevocationList]]:
    """Sign all active generations before committing any exported state."""
    crl_time = now_utc(strip_microseconds=True)
    crls = []
    for item in prepared:
        item.params["crl_time"] = crl_time
        crl = (
            _build_crl(
                item.params, crl_number=number, ca_cert=item.cert, private_key=item.key
            )
            if rebuild
            else item.existing
        )
        if crl is None:
            raise ValueError("Missing existing CRL")
        crls.append((item.params, crl))
    return crls


def _store_status(
    params: dict[str, Any], status: dict[str, dict[str, Any]]
) -> tuple[bool, dict[str, dict[str, Any]]]:
    """Persist retirement deadlines without opening any retired signing keys."""
    changed = False
    generations = {}
    for identity, state in status.items():
        changed = (
            _write_json(
                str(
                    generation_root(params["base_dir"], params["name"])
                    / identity
                    / "status.json"
                ),
                state,
                params.get("owner"),
                params.get("group"),
                "0644",
            )
            or changed
        )
        if state["retired"]:
            paths = _generation_params(params, identity)["paths"]
            generations[identity] = {
                **state,
                "paths": {
                    key: path for key, path in paths.items() if Path(path).exists()
                },
            }
    return changed, generations


def _store_crls(
    params: dict[str, Any],
    current: x509.Certificate,
    prepared: list[CrlGeneration],
    status: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Reserve the shared number, then persist status, revocations and CRL exports."""
    rebuild = any(item.changed for item in prepared)
    number = last_crl_number(params["base_dir"], params["name"]) + int(rebuild)
    crls = _build_crls(prepared, number, rebuild)
    changed, generations = _store_status(params, status)
    changed = retain_generation(params, current) or changed
    changed = store_crl_number(params, number) or changed or rebuild
    inventory_changed = False
    for generation_params, crl in crls:
        inventory_changed = (
            update_crl_inventory(generation_params, crl) or inventory_changed
        )
        changed = _write_crls(generation_params, crl) or changed
        identity = generation_params["generation_id"]
        generations[identity] = {
            **status[identity],
            "paths": generation_params["paths"],
            "crl_number": number,
        }
    return {
        "changed": changed or inventory_changed,
        "inventory_changed": inventory_changed,
        "generations": generations,
        "crl_number": number,
    }


def ensure_crls(params: dict[str, Any]) -> dict[str, Any]:
    """Prepare all CRLs first, then reserve numbers and persist state and exports."""
    params = dict(params)
    params["formats"] = _formats(params.get("formats"))
    params["revoked_certificates"] = resolve_revocation_entries(
        base_dir=params["base_dir"],
        authority=params["name"],
        entries=params["revoked_certificates"],
    )
    current = load_certificate(f"{params['base_dir']}/ca/{params['name']}-ca.pem")
    current_id = generation_id(current.subject, current.public_key())
    issuers = ca_history(params["base_dir"], params["name"])
    records = issued_history(params["base_dir"], params["name"], issuers)
    params["legacy_generation"] = _legacy_id(
        params["base_dir"],
        params["name"],
        current_id,
        str(params.get("legacy_generation") or ""),
    )
    deadlines = retirement_times(issuers, records)
    crl_time = now_utc(strip_microseconds=True)
    status = {
        identity: {
            "retire_at": timestamp_z(deadlines[identity]),
            "retired": identity != current_id and deadlines[identity] <= crl_time,
        }
        for identity in issuers
    }
    previous_number = last_crl_number(params["base_dir"], params["name"])
    prepared = [
        _prepare_crl(
            {
                **params,
                "crl_stop_at": deadlines[identity] if identity != current_id else None,
            },
            identity,
            cert,
            previous_number,
        )
        for identity, cert in issuers.items()
        if not status[identity]["retired"]
    ]
    result = _store_crls(params, current, prepared, status)
    revoked = {str(entry["serial_number"]) for entry in params["revoked_certificates"]}
    conflicts = [
        {
            "name": record["name"],
            "serial_number": record["certificate"]["serial_number"],
            "generation_id": record["issuer_generation"],
        }
        for record in records
        if legacy_references(params["name"], record)
        and record["issuer_generation"] != params["legacy_generation"]
        and record["certificate"]["serial_number"] not in revoked
        and (parse_datetime(record["certificate"]["not_valid_after"]) or crl_time)
        > crl_time
    ]
    return {
        **result,
        "formats": params["formats"],
        "legacy_generation": params["legacy_generation"],
        "migration_conflicts": conflicts,
        "paths": result["generations"][current_id]["paths"],
    }
