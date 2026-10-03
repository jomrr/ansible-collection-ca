# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

Ca inventory records helpers."""

from __future__ import annotations

from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_results import (
    CertificateMetadata,
    CertificateResult,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl_models import CrlPlan
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_store import (
    record_path,
    write_json,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_summary import (
    certificate_crl_number,
    certificate_summary,
    crl_authority_key_identifier,
    crl_update,
    oid_name,
    revoked_from_crl,
)
from ansible_collections.jomrr.ca.plugins.module_utils._paths import (
    authority_paths,
    certificate_paths,
)
from ansible_collections.jomrr.ca.plugins.module_utils._renewal import (
    renewal_policy,
    renewal_status,
)
from ansible_collections.jomrr.ca.plugins.module_utils._time import timestamp_z
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    load_certificate,
)

try:
    from cryptography import x509
except ImportError:
    pass


def _certificate_record_paths(
    base_dir: str,
    certificate: CertificateMetadata,
) -> dict[str, str]:
    """Return deterministic managed artifact paths for a certificate record."""
    paths = certificate_paths(
        base_dir, str(certificate["name"]), str(certificate.get("output_dir") or "")
    )
    formats = {str(item).lower() for item in certificate.get("formats", [])}
    keys = {"output_dir", "csr", "certificate_pem", "chain"}
    if not certificate.get("csr_mode"):
        keys.add("private_key")
    if "der" in formats:
        keys.add("certificate_der")
    if "txt" in formats:
        keys.add("certificate_text")
    if "fullchain" in formats:
        keys.add("fullchain")
    if "fritzbox" in formats:
        keys.add("fritzbox_bundle")
    if "pfx" in formats:
        keys.add("pkcs12_pfx")
    if "p12" in formats:
        keys.add("pkcs12_p12")
    return {key: paths[key] for key in sorted(keys)}


def record_authority_inventory(
    params: dict[str, Any],
    result: CertificateResult,
) -> bool:
    """Record current authority state as an internal inventory fragment."""
    base_dir = str(params["base_dir"]).rstrip("/")
    name = str(params["name"])
    cert = load_certificate(result["cert_path"])
    parent = str(params.get("parent") or name)
    self_signed = parent == name
    paths = authority_paths(base_dir, name, include_chain=not self_signed)
    certificate = certificate_summary(cert)
    record = {
        "record_type": "authority",
        "schema_version": 1,
        "name": name,
        "common_name": str(params.get("common_name") or ""),
        "parent": parent,
        "self_signed": self_signed,
        "days": params.get("days"),
        "renewal": renewal_policy(params.get("renewal")),
        "renewal_status": renewal_status(certificate, params.get("renewal")),
        "certificate": certificate,
        "paths": paths,
    }
    changed = write_json(
        record_path(
            base_dir,
            "authority_certificates",
            name,
            certificate["serial_number_hex"],
        ),
        record,
        params.get("owner"),
        params.get("group"),
        "0644",
    )
    return (
        write_json(
            record_path(base_dir, "authorities", name),
            record,
            params.get("owner"),
            params.get("group"),
            "0644",
        )
        or changed
    )


def record_certificate_inventory(
    params: dict[str, Any],
    model: CertificateMetadata,
    result: CertificateResult,
) -> bool:
    """Record managed certificate issuance state as inventory fragments."""
    base_dir = str(params["base_dir"]).rstrip("/")
    name = str(model["name"])
    issuer = str(model["issuer"])
    cert = load_certificate(result["cert_path"])
    certificate = certificate_summary(cert)
    serial_hex = certificate["serial_number_hex"]
    paths = _certificate_record_paths(base_dir, model)
    record = {
        "record_type": "issued_certificate",
        "schema_version": 1,
        "name": name,
        "type": str(model.get("type", "")),
        "common_name": str(model.get("common_name", "")),
        "issuer": issuer,
        "days": model.get("days"),
        "formats": [str(item).lower() for item in model.get("formats", [])],
        "renewal": renewal_policy(model.get("renewal")),
        "certificate": certificate,
        "paths": paths,
    }
    pointer = {
        "record_type": "current_certificate",
        "schema_version": 1,
        "name": name,
        "issuer": issuer,
        "serial_number_hex": serial_hex,
        "fingerprints": certificate["fingerprints"],
    }
    changed = write_json(
        record_path(base_dir, "issued_certificates", issuer, serial_hex),
        record,
        params.get("owner"),
        params.get("group"),
        "0644",
    )
    return (
        write_json(
            record_path(base_dir, "current_certificates", name),
            pointer,
            params.get("owner"),
            params.get("group"),
            "0644",
        )
        or changed
    )


def record_crl_inventory(
    plan: CrlPlan,
    crl: x509.CertificateRevocationList,
    crl_format: str,
    path: str,
) -> bool:
    """Record CRL and revocation state as internal inventory fragments."""
    base_dir = plan.request.context.base_dir.rstrip("/")
    authority = plan.request.context.name
    record = {
        "generation_id": plan.identity,
        "record_type": "crl",
        "schema_version": 1,
        "authority": authority,
        "format": crl_format,
        "path": path,
        "issuer": crl.issuer.rfc4514_string(),
        "last_update": timestamp_z(crl_update(crl, "last_update")),
        "next_update": timestamp_z(crl_update(crl, "next_update")),
        "signature_algorithm": oid_name(crl.signature_algorithm_oid),
        "crl_number": certificate_crl_number(crl),
        "authority_key_identifier": crl_authority_key_identifier(crl),
        "revoked_certificates": revoked_from_crl(crl),
    }
    generation = plan.suffix
    record_name = f"{generation}-{crl_format}" if generation else crl_format
    changed = write_json(
        record_path(base_dir, "crls", authority, record_name),
        record,
        plan.request.context.attributes.owner,
        plan.request.context.attributes.group,
        "0644",
    )
    for entry in plan.request.revoked_certificates:
        event = entry
        changed = (
            write_json(
                record_path(
                    base_dir,
                    "revocations",
                    authority,
                    event["serial_number_hex"],
                ),
                event,
                plan.request.context.attributes.owner,
                plan.request.context.attributes.group,
                "0644",
            )
            or changed
        )
    return changed
