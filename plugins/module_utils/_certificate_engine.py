# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

Shared certificate dispatcher implementation for the CA collection."""

from __future__ import annotations

from collections import Counter
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_args import (
    authority_list_argument,
    certificate_options,
)
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_results import (
    CertificateMetadata,
    CertificateResult,
)
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificateOperation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory import (
    update_certificate_inventory,
    update_certificates_inventory,
)
from ansible_collections.jomrr.ca.plugins.module_utils._profiles import (
    CERTIFICATE_DEFAULT_FORMATS,
    CERTIFICATE_PROFILE_DEFAULTS,
    apply_certificate_profile,
)
from ansible_collections.jomrr.ca.plugins.module_utils._validation import (
    authority_map,
    require_value,
    safe_name,
    string_value,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509 import (
    ensure_x509_operation,
    ensure_x509_operations,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_extensions import (
    basic_constraints,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_params import (
    with_derived_paths,
)

SUPPORTED_FORMATS = {"pem", "der", "txt", "pfx", "p12", "fullchain", "fritzbox"}


def certificate_common_argument_spec() -> dict[str, dict[str, Any]]:
    """Return the shared argument spec for certificate dispatcher modules."""
    return {
        "base_dir": {"type": "path", "required": True},
        "base_url": {"type": "str", "default": ""},
        "ca_name": {"type": "str", "default": ""},
        "certificate_types": {"type": "dict", "required": True},
        "authorities": authority_list_argument(),
        "kerberos_realm": {"type": "str", "default": ""},
        "subject": {"type": "dict", "default": {}},
        "renewal": {"type": "dict", "default": {}},
        "owner": {"type": "str"},
        "group": {"type": "str"},
        "force": {"type": "bool", "default": False},
    }


def single_certificate_argument_spec() -> dict[str, dict[str, Any]]:
    """Return the argument spec for the single-certificate module."""
    spec = certificate_common_argument_spec()
    spec["certificate"] = {
        "type": "dict",
        "required": True,
        "options": certificate_options(),
    }
    return spec


def batch_certificate_argument_spec() -> dict[str, dict[str, Any]]:
    """Return the argument spec for the certificate batch module."""
    spec = certificate_common_argument_spec()
    spec["certificates"] = {
        "type": "list",
        "elements": "dict",
        "required": True,
        "options": certificate_options(),
    }
    return spec


def _as_list(value: Any) -> list[Any]:
    """Return a list value or raise a module error."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise ValueError(f"Expected a list, got {type(value).__name__}")


def _as_dict(value: Any, context: str) -> dict[str, Any]:
    """Return a dictionary value or raise a contextual module error."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    raise ValueError(f"{context} must be a dictionary")


def _certificate_profile(
    params: dict[str, Any],
    certificate: dict[str, Any],
    csr_mode: bool,
    cert_type: str,
    authorities: dict[str, dict[str, Any]],
) -> tuple[str, str, str, Any]:
    """Validate and resolve the profile, issuer and lifetime."""
    name = certificate["name"]
    if cert_type not in CERTIFICATE_PROFILE_DEFAULTS:
        raise ValueError(f"Certificate {name} uses unknown profile {cert_type}")

    certificate_types = _as_dict(params.get("certificate_types"), "certificate_types")
    if cert_type not in certificate_types:
        raise ValueError(f"Certificate {name} uses unknown type {cert_type}")

    profile = _as_dict(certificate_types[cert_type], f"Certificate type {cert_type}")
    issuer = string_value(
        require_value(profile, "issuer", f"Certificate type {cert_type}")
    )
    if issuer not in authorities:
        raise ValueError(
            f"Certificate type {cert_type} references unknown issuer {issuer}"
        )

    issuer_authority = authorities[issuer]
    if (
        csr_mode
        and string_value(issuer_authority.get("parent")).strip() == issuer
        and not basic_constraints(certificate.get("basic_constraints")).ca
    ):
        raise ValueError(f"Certificate {name} CSR signing requires an issuing CA")
    issuer_passphrase = string_value(
        require_value(issuer_authority, "key_passphrase", f"Authority {issuer}")
    )
    default_days = issuer_authority.get("default_days")
    days = certificate.get("days", default_days)
    if days is None or string_value(days) == "":
        raise ValueError(
            f"Certificate {name} needs days or issuer authority {issuer} "
            "needs default_days"
        )

    for field in _as_list(profile.get("required_fields")):
        require_value(certificate, string_value(field), f"Certificate {name}")

    return cert_type, issuer, issuer_passphrase, days


def _merged_setting(
    params: dict[str, Any],
    certificate: dict[str, Any],
    field: str,
    name: str,
) -> dict[str, Any]:
    """Overlay certificate settings on the common subject or renewal policy."""
    result = dict(_as_dict(params.get(field), field))
    result.update(_as_dict(certificate.get(field), f"Certificate {name} {field}"))
    return result


def _resolve_certificate(
    params: dict[str, Any],
    certificate: dict[str, Any] | None,
    authorities: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Resolve context and profile input before constructing the typed operation."""
    certificate = _as_dict(
        params.get("certificate") if certificate is None else certificate,
        "certificate",
    )
    certificate = {
        key: value for key, value in certificate.items() if value is not None
    }
    name = safe_name(require_value(certificate, "name", "Certificate"), "Certificate")
    certificate["name"] = name
    csr_path = string_value(certificate.get("csr_path")).strip()
    csr_content = string_value(certificate.get("csr_content")).strip()
    csr_mode = bool(csr_path or csr_content)
    if csr_path and csr_content:
        raise ValueError(f"Certificate {name} uses both csr_path and csr_content")

    cert_type = string_value(
        require_value(certificate, "type", f"Certificate {name}")
    ).strip()
    # Resolve CA defaults before deciding whether a root may sign the request.
    certificate = {
        "basic_constraints": CERTIFICATE_PROFILE_DEFAULTS.get(cert_type, {}).get(
            "basic_constraints", ["CA:FALSE"]
        ),
        **certificate,
    }
    if csr_mode:
        common_name = string_value(certificate.get("common_name")).strip()
    else:
        common_name = string_value(
            require_value(certificate, "common_name", f"Certificate {name}")
        ).strip()

    cert_type, issuer, issuer_passphrase, days = _certificate_profile(
        params, certificate, csr_mode, cert_type, authorities
    )

    model = dict(certificate)
    model.update(
        {
            "name": name,
            "type": cert_type,
            "common_name": common_name,
            "issuer": issuer,
            "days": days,
            "formats": certificate.get(
                "formats", CERTIFICATE_DEFAULT_FORMATS[cert_type]
            ),
            "subject": _merged_setting(params, certificate, "subject", name),
            "renewal": _merged_setting(params, certificate, "renewal", name),
            "csr_source_path": csr_path,
        }
    )
    if cert_type == "mskdc":
        model["krb5_realm"] = (
            string_value(certificate.get("krb5_realm") or params.get("kerberos_realm"))
            .strip()
            .upper()
        )

    return {
        **model,
        "base_dir": params["base_dir"],
        "base_url": params["base_url"],
        "ca_name": params["ca_name"],
        "signer_key_passphrase": issuer_passphrase,
        "owner": params["owner"],
        "group": params["group"],
        "force": params["force"],
    }


def _certificate_metadata(operation: CertificateOperation) -> CertificateMetadata:
    """Project validated input onto the public inventory schema without reparsing."""
    request = operation.request
    return {
        "name": request["name"],
        "type": request["profile"],
        "common_name": request["subject"].common_name,
        "issuer": request["issuer"].name,
        "days": request["days"],
        "formats": request["exports"].formats,
        "output_dir": request["exports"].output_dir,
        "renewal": request["renewal"],
        "csr_mode": request["csr"].external,
    }


def prepare_certificate_artifacts(
    params: dict[str, Any],
    certificate: dict[str, Any] | None = None,
    *,
    authorities: dict[str, dict[str, Any]] | None = None,
) -> tuple[CertificateMetadata, CertificateOperation]:
    """Resolve one certificate into typed input and derived artifact paths."""
    values = _resolve_certificate(
        params,
        certificate,
        authority_map(params["authorities"]) if authorities is None else authorities,
    )
    values = apply_certificate_profile(
        values, values["type"], ca=basic_constraints(values.get("basic_constraints")).ca
    )
    operation = with_derived_paths(
        values, signed=True, authority=False, manage_directory=True, manage_chain=True
    )
    formats = set(operation.request["exports"].formats)
    unsupported = sorted(formats - SUPPORTED_FORMATS)
    if unsupported:
        raise ValueError(f"Unsupported certificate formats: {', '.join(unsupported)}")
    name = operation.request["name"]
    if operation.request["csr"].external and formats.intersection(
        {"pfx", "p12", "fritzbox"}
    ):
        raise ValueError(
            f"Certificate {name} CSR signing cannot create formats that require a "
            "private key: "
            + ", ".join(sorted(formats.intersection({"pfx", "p12", "fritzbox"})))
        )
    if (
        formats.intersection({"pfx", "p12"})
        and not operation.request["exports"].passphrase
    ):
        raise ValueError(
            f"Certificate {name} uses PFX/PKCS#12 output and requires pfx_passphrase"
        )
    return _certificate_metadata(operation), operation


def _ensure_prepared_certificate_artifacts(
    model: CertificateMetadata, operation: CertificateOperation
) -> CertificateResult:
    """Ensure artifacts for an already resolved certificate model."""
    result = ensure_x509_operation(
        operation,
        signed=True,
        manage_directory=True,
        manage_chain=True,
    )
    return _finalize_prepared_certificate_result(model, result)


def _finalize_prepared_certificate_result(
    model: CertificateMetadata,
    result: CertificateResult,
) -> CertificateResult:
    """Add dispatcher metadata to a prepared X.509 result."""
    result["name"] = model["name"]
    result["profile"] = model["type"]
    result["formats"] = [str(item).lower() for item in model["formats"]]
    return result


def _sync_model_common_name(
    model: CertificateMetadata, result: CertificateResult
) -> None:
    """Copy the issued subject's common name into inventory when needed."""
    if not model.get("common_name") and result.get("common_name"):
        model["common_name"] = result["common_name"]


def ensure_certificate_artifacts(
    params: dict[str, Any], certificate: dict[str, Any] | None = None
) -> CertificateResult:
    """Ensure one managed certificate and update its inventory state."""
    model, operation = prepare_certificate_artifacts(params, certificate)
    result = _ensure_prepared_certificate_artifacts(model, operation)
    _sync_model_common_name(model, result)
    inventory_changed = update_certificate_inventory(params, model, result)
    result["inventory_changed"] = inventory_changed
    result["changed"] = result["changed"] or inventory_changed
    return result


def _prepare_certificates(
    params: dict[str, Any], *, check_mode: bool
) -> list[tuple[CertificateMetadata, CertificateOperation]]:
    """Resolve shared batch context once before preparing individual operations."""
    certificates = _as_list(params.get("certificates"))
    authorities = authority_map(params["authorities"]) if certificates else {}
    prepared = []
    for index, certificate in enumerate(certificates):
        model, operation = prepare_certificate_artifacts(
            params,
            _as_dict(certificate, f"certificates[{index}]"),
            authorities=authorities,
        )
        operation.check_mode = check_mode
        prepared.append((model, operation))
    return prepared


def ensure_certificate_batch(
    params: dict[str, Any], *, check_mode: bool = False
) -> dict[str, Any]:
    """Ensure a list of managed certificates and compose inventory once."""
    prepared = _prepare_certificates(params, check_mode=check_mode)

    issuer_groups = Counter(model["issuer"] for model, _operation in prepared)

    raw_results = ensure_x509_operations(
        [operation for _model, operation in prepared],
        manage_directory=True,
        manage_chain=True,
    )
    results: dict[int, CertificateResult] = {}
    inventory_records: list[
        tuple[dict[str, Any], CertificateMetadata, CertificateResult]
    ] = []
    changed = False
    for index, ((model, _operation), raw_result) in enumerate(
        zip(prepared, raw_results)
    ):
        result = _finalize_prepared_certificate_result(model, raw_result)
        _sync_model_common_name(model, result)
        result["inventory_changed"] = result.pop("material_pending", False)
        result.pop("identity_changed", None)
        results[index] = result
        if not result["inventory_changed"]:
            inventory_records.append((params, model, result))
        changed = changed or bool(result["changed"])

    inventory_changed = update_certificates_inventory(
        inventory_records, check_mode=check_mode
    ) or any(result["inventory_changed"] for result in results.values())
    if inventory_changed:
        changed = True

    return {
        "changed": changed,
        "inventory_changed": inventory_changed,
        "count": len(results),
        "issuer_groups": dict(issuer_groups),
        "results": [results[index] for index in range(len(prepared))],
    }
