# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only certificate decisions; never generate keys or sign material."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ansible_collections.jomrr.ca.plugins.module_utils._authority_generations import (
    issuer_urls,
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
    certificate_matches,
    csr_matches,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_exports import (
    ensure_exports,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_extensions import (
    desired_extensions,
    subject_from_params,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    as_public_key,
    load_certificate,
    load_csr,
    load_existing_certificate,
    load_signing_key,
    public_key_bytes,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_material import (
    archive_existing_material,
    ensure_external_csr,
    reusable_key,
    validated_external_csr,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_state import (
    CertificateSpec,
    SignerMaterial,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_validation import (
    validate_signing_request,
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


def preview_signer(params: CertificateOperation, *, signed: bool) -> SignerMaterial:
    """Validate available issuer material, allowing a not-yet-created authority."""
    signer = SignerMaterial()
    if not signed:
        return signer
    try:
        signer.cert = load_certificate(params.paths["signer_cert_path"])
    except FileNotFoundError:
        return signer
    validate_signing_request(params, signer)
    signer.key = load_signing_key(
        params.paths["signer_key_path"], params.request["issuer"].passphrase
    )
    return signer


def _material(params: CertificateOperation, signer: SignerMaterial) -> PreviewMaterial:
    """Apply the same renewal, key selection and extension rules as issuance."""
    existing = load_existing_certificate(params.paths["cert_path"])
    renewal = certificate_renewal(params, existing)
    csr = validated_external_csr(params) if params.request["csr"].external else None
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
    spec = None
    if public is not None:
        subject = subject_from_params(params)
        if not params.paths["signer_cert_path"]:
            params.urls = issuer_urls(
                params,
                params.request["name"],
                subject,
                public,
            )
        spec = CertificateSpec(
            public,
            subject,
            desired_extensions(
                params,
                public,
                signer.cert.public_key() if signer.cert is not None else public,
            ),
        )
    return PreviewMaterial(existing, key, csr, spec, renewal)


def _csr_change(params: CertificateOperation, material: PreviewMaterial) -> bool:
    """Predict a CSR replacement or attribute correction without signing."""
    if material.csr is not None:
        return ensure_external_csr(params, material.csr)[1]
    if material.spec is None or params.request["force"]:
        return True
    try:
        existing = load_csr(params.paths["csr_path"])
    except MATERIAL_ERRORS:
        return True
    return not csr_matches(
        existing, material.spec, params.request["digest"]
    ) or file_needs_update(
        params.paths["csr_path"],
        params.request["storage"].attributes(),
    )


def _replacement(
    params: CertificateOperation, material: PreviewMaterial, signer: SignerMaterial
) -> bool:
    """Predict issuance from renewal and pure certificate field comparisons."""
    if material.spec is None or material.existing is None or material.renewal["renew"]:
        return True
    return not certificate_matches(
        material.existing,
        material.spec,
        signer.cert.subject if signer.cert is not None else material.spec.subject,
        signer.cert.public_key()
        if signer.cert is not None
        else as_public_key(material.spec.key),
        params.request["digest"],
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
    issuer_pending: bool = False,
) -> CertificateResult:
    """Predict artifacts and expose dependency state to the batch coordinator."""
    params.check_mode = True
    _validate_output_paths(params)
    signer = (
        preview_signer(params, signed=signed)
        if not issuer_pending
        else SignerMaterial()
    )
    material = _material(params, signer)
    pending = (
        issuer_pending
        or (signed and signer.cert is None)
        or _replacement(params, material, signer)
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
    if material.csr is not None:
        names = subject_from_params(params).get_attributes_for_oid(NameOID.COMMON_NAME)
        result.update(
            {
                "csr_mode": True,
                "common_name": str(names[0].value) if names else "",
                "fritzbox_bundle_path": "",
            }
        )
    return result
