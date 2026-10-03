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
    ExportChanges,
    MaterialChanges,
)
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificateOperation,
    RenewalDecision,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    ca_lock_path,
    file_locks,
)
from ansible_collections.jomrr.ca.plugins.module_utils._renewal import renewal_decision
from ansible_collections.jomrr.ca.plugins.module_utils._text import ensure_txt
from ansible_collections.jomrr.ca.plugins.module_utils._time import (
    certificate_not_valid_after,
    certificate_not_valid_before,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_chain import ordered_chain
from ansible_collections.jomrr.ca.plugins.module_utils._x509_constraints import (
    validate_issuer_constraints,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_exports import (
    chain_certificates,
    chain_content,
    ensure_chain,
    ensure_der,
    ensure_fritzbox_bundle,
    ensure_fullchain_bundle,
    ensure_pkcs12_exports,
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
    validated_external_csr,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_params import (
    with_derived_paths,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_policies import (
    validate_issuer_policies,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_state import (
    CertificateSpec,
    SignerMaterial,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import PrivateKey
    from cryptography import x509
    from cryptography.x509.oid import NameOID
except ImportError:
    pass


def _renewal_decision(
    params: CertificateOperation, existing_cert: x509.Certificate | None
) -> RenewalDecision:
    """Return renewal and rekey decisions for an existing certificate."""
    if existing_cert is None:
        return renewal_decision(
            force=bool(params.request["force"]),
            not_before=None,
            not_after=None,
            policy_value=params.request["renewal"],
        )
    return renewal_decision(
        force=bool(params.request["force"]),
        not_before=certificate_not_valid_before(existing_cert),
        not_after=certificate_not_valid_after(existing_cert),
        policy_value=params.request["renewal"],
    )


def ensure_x509(
    values: dict[str, Any],
    *,
    signed: bool,
    authority: bool = False,
    manage_directory: bool = False,
    manage_chain: bool = False,
) -> CertificateResult:
    """Ensure X.509 key, CSR, certificate, exports, and chain artifacts."""
    params = with_derived_paths(
        values,
        authority=authority,
        signed=signed,
        manage_directory=manage_directory,
        manage_chain=manage_chain,
    )
    lock_paths = [params.paths["lock_path"]]
    if authority:
        lock_paths.append(
            ca_lock_path(params.request["storage"].base_dir, "authority", "__graph__")
        )
    if signed:
        lock_paths.append(params.paths["signer_lock_path"])
    with file_locks(lock_paths):
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
        _validate_signing_request(params, signer)
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


def _validate_signing_request(
    params: CertificateOperation, signer: SignerMaterial
) -> x509.CertificateSigningRequest | None:
    """Check the entire issuer path before writing any request material."""
    if not signer.issuer_chain:
        issuer = params.request["issuer"].name
        signer.issuer_chain = ordered_chain(params.request["storage"].base_dir, issuer)
    signer.cert = signer.issuer_chain[0]
    csr = validated_external_csr(params) if params.request["csr"].external else None
    subject = subject_from_params(params)
    validate_issuer_constraints(
        params.request["name"],
        params.request["extensions"].basic_constraints,
        subject,
        signer.issuer_chain,
    )
    validate_issuer_policies(params, signer.cert)
    issuer = params.request["issuer"].name
    params.urls = issuer_urls(
        params.request["storage"].base_dir,
        params.request["publication"],
        issuer,
        signer.cert.subject,
        signer.cert.public_key(),
    )
    return csr


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


def _ensure_exports(
    params: CertificateOperation,
    cert: x509.Certificate,
    signer: SignerMaterial,
    key: PrivateKey | None,
    manage_chain: bool,
) -> ExportChanges:
    """Write the requested public and private certificate exports."""
    changes: ExportChanges = {
        "der_changed": ensure_der(params, cert),
        "txt_changed": ensure_txt(params, cert),
        "chain_changed": ensure_chain(params, signer.cert) if manage_chain else False,
        "pkcs12_changed": False,
        "fullchain_changed": False,
        "pkcs12_paths": {},
        "fritzbox_bundle_changed": False,
    }
    bundle_content = signer.chain_content
    extra_certs = signer.extra_certs
    if not params.request["authority"] and set(
        params.request["exports"].formats
    ).intersection({"pfx", "p12", "fullchain", "fritzbox"}):
        bundle_content = bundle_content or chain_content(params, signer.cert)
        if key is not None:
            extra_certs = extra_certs or chain_certificates(params, signer.cert)
    paths: dict[str, str] = {}
    if key is not None:
        changes["pkcs12_changed"], paths = ensure_pkcs12_exports(
            params, key, cert, extra_certs
        )
    changes["fullchain_changed"] = ensure_fullchain_bundle(params, cert, bundle_content)
    if key is not None:
        changes["fritzbox_bundle_changed"] = ensure_fritzbox_bundle(
            params, cert, bundle_content
        )
    changes["pkcs12_paths"] = paths
    return changes


def _result(
    params: CertificateOperation,
    changes: MaterialChanges,
    exports: ExportChanges,
    renewal: RenewalDecision,
) -> CertificateResult:
    """Combine artifact changes with stable result metadata."""
    result: CertificateResult = {
        "directory_changed": changes["directory_changed"],
        "archive_changed": changes["archive_changed"],
        "key_changed": changes["key_changed"],
        "csr_changed": changes["csr_changed"],
        "cert_changed": changes["cert_changed"],
        "der_changed": exports["der_changed"],
        "txt_changed": exports["txt_changed"],
        "chain_changed": exports["chain_changed"],
        "pkcs12_changed": exports["pkcs12_changed"],
        "fullchain_changed": exports["fullchain_changed"],
        "fritzbox_bundle_changed": exports["fritzbox_bundle_changed"],
        "pkcs12_paths": exports["pkcs12_paths"],
        "changed": any(changes.values())
        or any(value for name, value in exports.items() if name.endswith("_changed")),
        "formats": params.request["exports"].formats,
        "renewal": renewal,
        "csr_path": params.paths["csr_path"],
        "cert_path": params.paths["cert_path"],
        "txt_path": params.paths["txt_path"],
        "fullchain_path": params.paths["fullchain_path"],
        "fritzbox_bundle_path": params.paths["fritzbox_bundle_path"],
    }

    if "generation_changed" in changes:
        result["generation_changed"] = changes["generation_changed"]
    return result


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
    renewal = _renewal_decision(params, existing_cert)
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
    exports = _ensure_exports(params, cert, signer, None, manage_chain)
    common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {
        **_result(params, changes, exports, renewal),
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
    csr = _validate_signing_request(params, signer) if signed else None
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
    renewal = _renewal_decision(params, existing_cert)
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
            params.request["storage"].base_dir,
            params.request["publication"],
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
    exports = _ensure_exports(params, cert, signer, key, manage_chain)
    return _result(params, changes, exports, renewal)
