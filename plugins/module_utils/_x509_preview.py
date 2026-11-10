# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only certificate decisions; never generate keys or sign material."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ansible_collections.jomrr.ca.plugins.module_utils._authority_generations import (
    retain_generation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_results import (
    CertificateResult,
    ExportChanges,
    MaterialChanges,
    certificate_result,
)
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificateOperation,
    RenewalDecision,
)
from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    MATERIAL_ERRORS,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    FileAttributes,
    file_needs_update,
)
from ansible_collections.jomrr.ca.plugins.module_utils._renewal import (
    certificate_renewal,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_compare import (
    certificate_needs_replacement,
    csr_needs_replacement,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_exports import (
    ensure_exports,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    load_csr,
    load_existing_certificate,
    public_key_bytes,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_material import (
    archive_existing_material,
    ensure_external_csr,
    reusable_key,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_state import (
    CertificateSpec,
    SigningRequest,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_validation import (
    certificate_spec,
    prepare_signing_request,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import PrivateKey
    from cryptography import x509
    from cryptography.x509.oid import NameOID
except ImportError:
    pass


@dataclass
class PreviewMaterial:
    """Observed material and the desired spec, absent when a new key is needed."""

    existing: x509.Certificate | None
    key: PrivateKey | None
    csr: x509.CertificateSigningRequest | None
    spec: CertificateSpec | None
    renewal: RenewalDecision


def _material(params: CertificateOperation, request: SigningRequest) -> PreviewMaterial:
    """Apply the same renewal, key selection and extension rules as issuance."""
    existing = load_existing_certificate(params.paths["cert_path"])
    renewal = certificate_renewal(params, existing)
    csr = request.csr
    signer = request.signer
    if csr is not None:
        renewal["rekey"] = False
    key = None if csr is not None else reusable_key(params, rekey=renewal["rekey"])
    public = (
        csr.public_key()
        if csr is not None
        else key.public_key()
        if key is not None
        else None
    )
    spec = certificate_spec(
        params, public, signer.cert.public_key() if signer.cert is not None else public
    )
    return PreviewMaterial(existing, key, csr, spec, renewal)


def _csr_change(params: CertificateOperation, material: PreviewMaterial) -> bool:
    """Predict a CSR replacement or attribute correction without signing."""
    if material.csr is not None:
        return ensure_external_csr(params, material.csr)[1]
    try:
        existing = load_csr(params.paths["csr_path"])
    except MATERIAL_ERRORS:
        existing = None
    return csr_needs_replacement(params, existing, material.spec) or file_needs_update(
        params.paths["csr_path"],
        params.request["storage"].attributes(),
    )


def _pending_exports(
    params: CertificateOperation, *, manage_chain: bool
) -> ExportChanges:
    """Report exports that depend on the certificate that would be issued."""
    return {
        "der_changed": bool(params.paths["der_path"]),
        "txt_changed": bool(params.paths["txt_path"]),
        "chain_changed": manage_chain and bool(params.paths["chain_path"]),
        "pkcs12_changed": bool(params.paths["pkcs12_paths"]),
        "fullchain_changed": bool(params.paths["fullchain_path"]),
        "fritzbox_bundle_changed": bool(params.paths["fritzbox_bundle_path"]),
        "pkcs12_paths": params.paths["pkcs12_paths"],
    }


def _validate_output_paths(params: CertificateOperation) -> None:
    """Reject unsafe output paths even when future content cannot be generated."""
    private = {
        params.paths["key_path"],
        params.paths["fritzbox_bundle_path"],
        *params.paths["pkcs12_paths"].values(),
    }
    paths = [
        params.paths[key]
        for key in (
            "key_path",
            "csr_path",
            "cert_path",
            "der_path",
            "txt_path",
            "chain_path",
            "fullchain_path",
            "fritzbox_bundle_path",
        )
    ]
    for path in [*paths, *params.paths["pkcs12_paths"].values()]:
        if path:
            file_needs_update(
                path, params.request["storage"].attributes(private=path in private)
            )
            if Path(path).is_dir():
                raise ValueError(f"Refusing to write to directory path: {path}")


def preview_x509(
    params: CertificateOperation,
    *,
    signed: bool,
    manage_directory: bool = False,
    manage_chain: bool = False,
    request: SigningRequest | None = None,
) -> CertificateResult:
    """Predict artifacts and expose dependency state to the batch coordinator."""
    params.check_mode = True
    _validate_output_paths(params)
    request = request or prepare_signing_request(params)
    signer = request.signer
    material = _material(params, request)
    pending = (
        request.issuer_pending
        or (signed and signer.cert is None)
        or certificate_needs_replacement(
            params, material.existing, material.spec, signer, material.renewal
        )
    )
    storage = params.request["storage"]
    changes: MaterialChanges = {
        "directory_changed": manage_directory
        and file_needs_update(
            params.paths["directory_path"],
            FileAttributes(storage.owner, storage.group, storage.directory_mode),
        ),
        "key_changed": material.csr is None
        and (
            material.key is None
            or file_needs_update(
                params.paths["key_path"],
                storage.attributes(private=True),
            )
        ),
        "csr_changed": _csr_change(params, material),
        "cert_changed": pending
        or file_needs_update(params.paths["cert_path"], storage.attributes()),
        "archive_changed": pending
        and archive_existing_material(
            params,
            material.existing,
            include_private_key=material.key is None and material.csr is None,
        ),
    }
    if params.request["authority"]:
        changes["generation_changed"] = pending or (
            material.existing is not None
            and retain_generation(
                storage.base_dir,
                params.request["name"],
                material.existing,
                storage.attributes(),
                check_mode=True,
            )
        )
    if pending:
        exports = _pending_exports(params, manage_chain=manage_chain)
    else:
        if material.existing is None:
            raise ValueError("Missing certificate after comparison")
        exports = ensure_exports(
            params, material.existing, signer, material.key, manage_chain
        )
    result = certificate_result(params, changes, exports, material.renewal)
    result["material_pending"] = pending
    result["identity_changed"] = (
        material.spec is None
        or material.existing is None
        or (
            material.existing.subject != material.spec.subject
            or public_key_bytes(material.existing.public_key())
            != public_key_bytes(material.spec.key)
        )
    )
    if material.csr is not None and material.spec is not None:
        names = material.spec.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        result.update(
            {
                "csr_mode": True,
                "common_name": str(names[0].value) if names else "",
                "fritzbox_bundle_path": "",
            }
        )
    return result
