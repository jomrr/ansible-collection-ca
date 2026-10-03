# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

Ca inventory helpers."""

from __future__ import annotations

import json
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_results import (
    CertificateMetadata,
    CertificateResult,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl_models import CrlPlan
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    FileAttributes,
    file_lock,
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._input import InputValues
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_records import (
    record_authority_inventory,
    record_certificate_inventory,
    record_crl_inventory,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_revocation import (
    revocation_map,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_store import (
    inventory_document_path,
    inventory_lock_path,
    read_collection,
    read_json,
)
from ansible_collections.jomrr.ca.plugins.module_utils._renewal import renewal_status
from ansible_collections.jomrr.ca.plugins.module_utils._time import (
    now_utc,
    parse_datetime,
)

try:
    from cryptography import x509
except ImportError:
    pass


def update_authority_inventory(
    params: dict[str, Any],
    result: CertificateResult,
) -> bool:
    """Record authority fragments and compose inventory in one transaction."""
    base_dir = str(params["base_dir"]).rstrip("/")
    with file_lock(inventory_lock_path(base_dir)):
        changed = record_authority_inventory(params, result)
        return _compose_inventory_if_configured_unlocked(params) or changed


def update_certificate_inventory(
    params: dict[str, Any],
    model: CertificateMetadata,
    result: CertificateResult,
) -> bool:
    """Record certificate fragments and compose inventory in one transaction."""
    base_dir = str(params["base_dir"]).rstrip("/")
    with file_lock(inventory_lock_path(base_dir)):
        changed = record_certificate_inventory(params, model, result)
        return _compose_inventory_if_configured_unlocked(params) or changed


def update_certificates_inventory(
    records: list[tuple[dict[str, Any], CertificateMetadata, CertificateResult]],
) -> bool:
    """Record multiple certificate fragments and compose inventory once."""
    if not records:
        return False

    base_dir = str(records[0][0]["base_dir"]).rstrip("/")
    with file_lock(inventory_lock_path(base_dir)):
        changed = False
        for params, model, result in records:
            changed = record_certificate_inventory(params, model, result) or changed
        return _compose_inventory_if_configured_unlocked(records[0][0]) or changed


def update_crl_inventory(plan: CrlPlan, crl: x509.CertificateRevocationList) -> bool:
    """Record CRL fragments and compose inventory in one transaction."""
    request = plan.request
    with file_lock(inventory_lock_path(request.context.base_dir)):
        changed = False
        for crl_format, path in plan.paths.items():
            changed = record_crl_inventory(plan, crl, crl_format, path) or changed
        if request.context.ca_name:
            changed = (
                _write_composed_inventory_unlocked(
                    base_dir=request.context.base_dir,
                    ca_name=request.context.ca_name,
                    base_url=request.context.base_url,
                    attrs=FileAttributes(
                        request.context.attributes.owner,
                        request.context.attributes.group,
                    ),
                )
                or changed
            )
        return changed


def _status(
    record: dict[str, Any],
    revocations: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    """Return status for an issued certificate record."""
    issuer = str(record["issuer"])
    serial_hex = str(record["certificate"]["serial_number_hex"])
    revoked = revocations.get((issuer, serial_hex))
    if revoked is not None:
        return {"state": "revoked", "revocation": revoked}
    now = now_utc()
    not_before = parse_datetime(record["certificate"]["not_valid_before"])
    not_after = parse_datetime(record["certificate"]["not_valid_after"])
    if not_before is None or not_after is None:
        raise ValueError("certificate record must contain validity timestamps")
    if not_before > now:
        return {"state": "not_yet_valid"}
    if not_after <= now:
        return {"state": "expired"}
    return {"state": "valid"}


def _with_status(
    record: dict[str, Any],
    current_pointers: dict[str, dict[str, Any]],
    revocations: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    """Return an issued certificate with status and current flag."""
    result = dict(record)
    pointer = current_pointers.get(str(record["name"]), {})
    result["current"] = pointer.get("issuer") == record.get("issuer") and pointer.get(
        "serial_number_hex"
    ) == record.get("certificate", {}).get("serial_number_hex")
    result["status"] = _status(record, revocations)
    result["renewal_status"] = renewal_status(
        record["certificate"],
        record.get("renewal"),
    )
    return result


def _stored_base_url(base_dir: str) -> str:
    """Read shared publication metadata, allowing only absent inventory to default."""
    try:
        inventory = read_json(inventory_document_path(base_dir))
    except FileNotFoundError:
        return ""
    return InputValues(inventory).text("base_url")


def _compose_inventory_unlocked(
    *,
    base_dir: str,
    ca_name: str,
    base_url: str,
) -> dict[str, Any]:
    """Compose inventory JSON while the state lock is held."""
    authorities = sorted(
        read_collection(base_dir, "authorities"),
        key=lambda record: str(record.get("name", "")),
    )
    current_pointers = {
        str(record["name"]): record
        for record in read_collection(base_dir, "current_certificates")
    }
    revocations = sorted(
        read_collection(base_dir, "revocations"),
        key=lambda record: (
            str(record.get("issuer", "")),
            str(record.get("serial_number_hex", "")),
        ),
    )
    revocation_by_serial = revocation_map(revocations)
    issued = [
        _with_status(record, current_pointers, revocation_by_serial)
        for record in read_collection(base_dir, "issued_certificates")
    ]
    issued = sorted(
        issued,
        key=lambda record: (
            str(record.get("name", "")),
            str(record.get("issuer", "")),
            str(record.get("certificate", {}).get("serial_number_hex", "")),
        ),
    )
    crls = sorted(
        read_collection(base_dir, "crls"),
        key=lambda record: (
            str(record.get("authority", "")),
            str(record.get("format", "")),
        ),
    )
    authority_certificates = sorted(
        read_collection(base_dir, "authority_certificates"),
        key=lambda record: (
            str(record.get("name", "")),
            str(record.get("certificate", {}).get("serial_number_hex", "")),
        ),
    )
    return {
        "schema_version": 1,
        "ca_name": ca_name,
        "base_dir": str(base_dir).rstrip("/"),
        "base_url": base_url or _stored_base_url(base_dir),
        "authorities": authorities,
        "authority_certificates": authority_certificates,
        "certificates": [record for record in issued if record["current"]],
        "issued_certificates": issued,
        "revocations": revocations,
        "crls": crls,
    }


def compose_inventory(
    *,
    base_dir: str,
    ca_name: str,
    base_url: str,
) -> dict[str, Any]:
    """Compose inventory JSON from internal state fragments."""
    with file_lock(inventory_lock_path(base_dir)):
        return _compose_inventory_unlocked(
            base_dir=base_dir,
            ca_name=ca_name,
            base_url=base_url,
        )


def write_composed_inventory(
    *,
    base_dir: str,
    ca_name: str,
    base_url: str,
    attrs: FileAttributes | None = None,
    force: bool = False,
) -> bool:
    """Write the composed CA inventory file in an inventory transaction."""
    with file_lock(inventory_lock_path(base_dir)):
        return _write_composed_inventory_unlocked(
            base_dir=base_dir,
            ca_name=ca_name,
            base_url=base_url,
            attrs=attrs,
            force=force,
        )


def _write_composed_inventory_unlocked(
    *,
    base_dir: str,
    ca_name: str,
    base_url: str,
    attrs: FileAttributes | None = None,
    force: bool = False,
) -> bool:
    """Write the composed CA inventory file while the state lock is held."""
    content = (
        json.dumps(
            _compose_inventory_unlocked(
                base_dir=base_dir,
                ca_name=ca_name,
                base_url=base_url,
            ),
            indent=2,
            sort_keys=True,
        ).encode()
        + b"\n"
    )
    return write_file(
        inventory_document_path(base_dir),
        content,
        attrs or FileAttributes(),
        force=force,
    )


def _compose_inventory_if_configured_unlocked(params: dict[str, Any]) -> bool:
    """Compose the central CA inventory if configured while the state lock is held."""
    ca_name = str(params.get("ca_name") or "")
    if not ca_name:
        return False
    return _write_composed_inventory_unlocked(
        base_dir=str(params["base_dir"]),
        ca_name=ca_name,
        base_url=str(params.get("base_url") or ""),
        attrs=FileAttributes(params.get("owner"), params.get("group")),
    )


def compose_inventory_if_configured(params: dict[str, Any]) -> bool:
    """Compose the central CA inventory when module parameters provide a CA name."""
    with file_lock(inventory_lock_path(str(params["base_dir"]))):
        return _compose_inventory_if_configured_unlocked(params)
