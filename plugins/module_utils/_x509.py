# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

X.509 helpers."""

from __future__ import annotations

from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._authority_generations import (
    issuer_urls,
    retain_generation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_results import (
    CertificateResult,
    MaterialChanges,
    certificate_result,
)
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificateOperation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    ca_lock_path,
    file_locks,
)
from ansible_collections.jomrr.ca.plugins.module_utils._renewal import (
    certificate_renewal,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_exports import (
    chain_certificates,
    chain_content,
    ensure_exports,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_extensions import (
    desired_extensions,
    subject_from_params,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    load_certificate,
    load_existing_certificate,
    load_signing_key,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_material import (
    archive_existing_material,
    ensure_certificate,
    ensure_csr,
    ensure_directory,
    ensure_external_csr,
    ensure_key,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_params import (
    with_derived_paths,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_state import (
    CertificateSpec,
    SignerMaterial,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_validation import (
    validate_signing_request,
)

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
except ImportError:
    pass


def ensure_x509(
    values: dict[str, Any],
    *,
    signed: bool,
    authority: bool = False,
    manage_directory: bool = False,
    manage_chain: bool = False,
) -> CertificateResult:
    """Ensure X.509 artifacts with the requested export lifecycle."""
    params = with_derived_paths(
        values,
        authority=authority,
        signed=signed,
        manage_directory=manage_directory,
        manage_chain=manage_chain,
    )
    return ensure_x509_operation(
        params,
        signed=signed,
        manage_directory=manage_directory,
        manage_chain=manage_chain,
    )


def ensure_x509_operation(
    params: CertificateOperation,
    *,
    signed: bool,
    manage_directory: bool = False,
    manage_chain: bool = False,
    held_locks: frozenset[str] = frozenset(),
) -> CertificateResult:
    """Execute derived state; held_locks must be owned by the calling operation."""
    lock_paths = [params.paths["lock_path"]]
    if params.request["authority"]:
        lock_paths.append(
            ca_lock_path(params.request["storage"].base_dir, "authority", "__graph__")
        )
    if signed:
        lock_paths.append(params.paths["signer_lock_path"])
    with file_locks(path for path in lock_paths if path not in held_locks):
        return _ensure_x509_locked(
            params,
            signed=signed,
            manage_directory=manage_directory,
            manage_chain=manage_chain,
        )


def ensure_x509_many(
    params_list: list[dict[str, Any]],
    *,
    signed: bool,
    authority: bool = False,
    manage_directory: bool = False,
    manage_chain: bool = False,
) -> list[CertificateResult]:
    """Ensure multiple X.509 objects while caching shared signer material."""
    derived_params = [
        with_derived_paths(
            params,
            authority=authority,
            signed=signed,
            manage_directory=manage_directory,
            manage_chain=manage_chain,
        )
        for params in params_list
    ]
    if not signed or authority:
        return [
            ensure_x509(
                params,
                signed=signed,
                authority=authority,
                manage_directory=manage_directory,
                manage_chain=manage_chain,
            )
            for params in params_list
        ]
    groups: dict[str, list[tuple[int, CertificateOperation]]] = {}
    for index, derived in enumerate(derived_params):
        groups.setdefault(str(derived.paths["signer_lock_path"]), []).append(
            (index, derived)
        )
    results: dict[int, CertificateResult] = {}
    for signer_lock_path, group in groups.items():
        with file_locks(
            [signer_lock_path, *(params.paths["lock_path"] for _index, params in group)]
        ):
            signer = _group_signer(group)
            for index, params in group:
                results[index] = _ensure_x509_locked(
                    params,
                    signed=signed,
                    manage_directory=manage_directory,
                    manage_chain=manage_chain,
                    signer=signer,
                )
    return [results[index] for index in range(len(params_list))]


def _group_signer(group: list[tuple[int, CertificateOperation]]) -> SignerMaterial:
    """Load and validate issuer material once for a locked batch."""
    first = group[0][1]
    signer = SignerMaterial(cert=load_certificate(first.paths["signer_cert_path"]))
    for _index, params in group:
        validate_signing_request(params, signer)
    signer.key = load_signing_key(
        first.paths["signer_key_path"], first.request["issuer"].passphrase
    )
    if any(
        set(params.request["exports"].formats).intersection(
            {"pfx", "p12", "fullchain", "fritzbox"}
        )
        for _index, params in group
    ):
        signer.chain_content = chain_content(first, signer.cert)
        signer.extra_certs = chain_certificates(first, signer.cert)
    return signer


def _directory_change(params: CertificateOperation, manage_directory: bool) -> bool:
    """Enforce the certificate directory when requested."""
    return bool(
        manage_directory
        and ensure_directory(
            params.paths["directory_path"],
            params.request["storage"].owner,
            params.request["storage"].group,
            params.request["storage"].directory_mode,
        )
    )


def _ensure_x509_from_csr_locked(
    params: CertificateOperation,
    csr: x509.CertificateSigningRequest,
    *,
    manage_directory: bool,
    manage_chain: bool,
    signer: SignerMaterial,
) -> CertificateResult:
    """Ensure one signed certificate from an externally supplied CSR."""
    unsupported = sorted(
        set(params.request["exports"].formats).intersection({"pfx", "p12", "fritzbox"})
    )
    if unsupported:
        raise ValueError(
            "CSR signing cannot create formats that require a private key: "
            + ", ".join(unsupported)
        )
    changes: MaterialChanges = {
        "key_changed": False,
        "csr_changed": False,
        "cert_changed": False,
        "directory_changed": _directory_change(params, manage_directory),
        "archive_changed": False,
    }
    existing_cert = load_existing_certificate(params.paths["cert_path"])
    renewal = certificate_renewal(params, existing_cert)
    renewal["rekey"] = False
    csr, changes["csr_changed"] = ensure_external_csr(params, csr)
    if signer.key is None:
        signer.key = load_signing_key(
            params.paths["signer_key_path"], params.request["issuer"].passphrase
        )
    if signer.cert is None:
        signer.cert = load_certificate(params.paths["signer_cert_path"])
    spec = CertificateSpec(
        csr.public_key(),
        subject_from_params(params),
        desired_extensions(
            params,
            csr.public_key(),
            signer.cert.public_key(),
        ),
    )
    cert, changes["cert_changed"] = ensure_certificate(
        params, spec, signer, renewal, existing_cert
    )
    exports = ensure_exports(params, cert, signer, None, manage_chain)
    common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {
        **certificate_result(params, changes, exports, renewal),
        "csr_mode": True,
        "common_name": str(common_names[0].value) if common_names else "",
        "fritzbox_bundle_path": "",
    }


def _ensure_x509_locked(
    params: CertificateOperation,
    *,
    signed: bool,
    manage_directory: bool,
    manage_chain: bool,
    signer: SignerMaterial | None = None,
) -> CertificateResult:
    """Ensure one X.509 object while holding its object lock."""
    signer = signer or SignerMaterial()
    csr = validate_signing_request(params, signer) if signed else None
    if params.request["csr"].external:
        if csr is None:
            raise ValueError("CSR signing requires an issuing CA")
        return _ensure_x509_from_csr_locked(
            params,
            csr,
            manage_directory=manage_directory,
            manage_chain=manage_chain,
            signer=signer,
        )
    changes: MaterialChanges = {
        "key_changed": False,
        "csr_changed": False,
        "cert_changed": False,
        "directory_changed": _directory_change(params, manage_directory),
        "archive_changed": False,
    }
    existing_cert = load_existing_certificate(params.paths["cert_path"])
    if params.request["authority"] and existing_cert is not None:
        changes["generation_changed"] = retain_generation(
            params.request["storage"].base_dir,
            params.request["name"],
            existing_cert,
            params.request["storage"].attributes(),
        )
    renewal = certificate_renewal(params, existing_cert)
    if renewal["rekey"]:
        changes["archive_changed"] = archive_existing_material(
            params, existing_cert, include_private_key=True
        )
    key, changes["key_changed"] = ensure_key(
        params, rekey=renewal["rekey"], existing_cert=existing_cert
    )
    subject = subject_from_params(params)
    if signer.key is None:
        signer.key = (
            load_signing_key(
                params.paths["signer_key_path"], params.request["issuer"].passphrase
            )
            if signed
            else key
        )
    if not signed:
        params.urls = issuer_urls(
            params,
            params.request["name"],
            subject,
            key.public_key(),
        )
    extensions = desired_extensions(
        params,
        key.public_key(),
        signer.cert.public_key() if signer.cert is not None else key.public_key(),
    )
    _csr, changes["csr_changed"] = ensure_csr(params, key, subject, extensions)
    cert, changes["cert_changed"] = ensure_certificate(
        params,
        CertificateSpec(key, subject, extensions),
        signer,
        renewal,
        existing_cert,
    )
    if params.request["authority"]:
        changes["generation_changed"] = retain_generation(
            params.request["storage"].base_dir,
            params.request["name"],
            cert,
            params.request["storage"].attributes(),
        ) or changes.get("generation_changed", False)
    exports = ensure_exports(params, cert, signer, key, manage_chain)
    return certificate_result(params, changes, exports, renewal)
