# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

X.509 helpers."""

from __future__ import annotations

from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    CRYPTOGRAPHY_IMPORT_ERROR,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    ca_lock_path,
    file_locks,
    sanitize_error,
)
from ansible_collections.jomrr.ca.plugins.module_utils._renewal import renewal_decision
from ansible_collections.jomrr.ca.plugins.module_utils._text import ensure_txt
from ansible_collections.jomrr.ca.plugins.module_utils._time import (
    certificate_not_valid_after,
    certificate_not_valid_before,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_exports import (
    _chain_certificates,
    _chain_content,
    _ensure_chain,
    _ensure_der,
    _ensure_fritzbox_bundle,
    _ensure_fullchain_bundle,
    _ensure_pkcs12_exports,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_extensions import (
    _csr_subject_alt_name,
    _desired_extensions,
    subject_from_params,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    _csr_common_name,
    _load_existing_certificate,
    digest_algorithm,
    load_certificate,
    load_certificates,
    signature_algorithm,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    load_signing_key as load_private_key,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_material import (
    _archive_existing_material,
    _ensure_certificate,
    _ensure_csr,
    _ensure_directory,
    _ensure_external_csr,
    _ensure_key,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_params import (
    _external_csr_configured,
    _with_derived_paths,
    ca_authority_argument_spec,
    certificate_params,
    normalize_formats,
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
except ImportError:
    pass


__all__ = [
    "CRYPTOGRAPHY_IMPORT_ERROR",
    "_ensure_x509_from_csr_locked",
    "_ensure_x509_locked",
    "_renewal_decision",
    "ca_authority_argument_spec",
    "certificate_params",
    "digest_algorithm",
    "ensure_x509",
    "ensure_x509_many",
    "load_certificate",
    "load_certificates",
    "load_private_key",
    "normalize_formats",
    "sanitize_error",
    "signature_algorithm",
    "subject_from_params",
]


def _renewal_decision(
    params: dict[str, Any], existing_cert: x509.Certificate | None
) -> dict[str, Any]:
    """Return renewal and rekey decisions for an existing certificate."""
    if existing_cert is None:
        return renewal_decision(
            force=bool(params.get("force")),
            not_before=None,
            not_after=None,
            policy_value=params.get("renewal"),
        )
    return renewal_decision(
        force=bool(params.get("force")),
        not_before=certificate_not_valid_before(existing_cert),
        not_after=certificate_not_valid_after(existing_cert),
        policy_value=params.get("renewal"),
    )


def ensure_x509(
    params: dict[str, Any],
    *,
    signed: bool,
    authority: bool = False,
    manage_directory: bool = False,
    manage_chain: bool = False,
) -> dict[str, Any]:
    """Ensure X.509 key, CSR, certificate, exports, and chain artifacts."""
    params = _with_derived_paths(
        params,
        authority=authority,
        signed=signed,
        manage_directory=manage_directory,
        manage_chain=manage_chain,
    )
    lock_paths = [params["lock_path"]]
    if authority:
        lock_paths.append(ca_lock_path(params["base_dir"], "authority", "__graph__"))
    if signed:
        lock_paths.append(params["signer_lock_path"])
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
) -> list[dict[str, Any]]:
    """Ensure multiple X.509 objects while caching shared signer material."""
    derived_params = [
        _with_derived_paths(
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
    groups: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, derived in enumerate(derived_params):
        groups.setdefault(str(derived["signer_lock_path"]), []).append((index, derived))
    results: list[dict[str, Any]] = [{} for _item in params_list]
    for signer_lock_path, group in groups.items():
        with file_locks(
            [signer_lock_path, *(params["lock_path"] for _index, params in group)]
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
    return results


def _group_signer(group: list[tuple[int, dict[str, Any]]]) -> SignerMaterial:
    """Load and validate issuer material once for a locked batch."""
    first = group[0][1]
    signer = SignerMaterial(cert=load_certificate(first["signer_cert_path"]))
    for _index, params in group:
        if signer.cert is not None:
            validate_issuer_policies(params, signer.cert)
    signer.key = load_private_key(
        first["signer_key_path"], first["signer_key_passphrase"]
    )
    if any(
        set(params["formats"]).intersection({"pfx", "p12", "fullchain", "fritzbox"})
        for _index, params in group
    ):
        signer.chain_content = _chain_content(first, signer.cert)
        signer.extra_certs = _chain_certificates(first, signer.cert)
    return signer


def _directory_change(params: dict[str, Any], manage_directory: bool) -> bool:
    """Enforce the certificate directory when requested."""
    return bool(
        manage_directory
        and _ensure_directory(
            params["directory_path"],
            params["owner"],
            params["group"],
            params["directory_mode"],
        )
    )


def _ensure_exports(
    params: dict[str, Any],
    cert: x509.Certificate,
    signer: SignerMaterial,
    key: PrivateKey | None,
    manage_chain: bool,
) -> dict[str, Any]:
    """Write the requested public and private certificate exports."""
    changes = {
        "der_changed": _ensure_der(params, cert),
        "txt_changed": ensure_txt(params, cert),
        "chain_changed": _ensure_chain(params) if manage_chain else False,
        "pkcs12_changed": False,
        "fritzbox_bundle_changed": False,
    }
    chain_content = signer.chain_content
    extra_certs = signer.extra_certs
    if not params["authority"] and set(params["formats"]).intersection(
        {"pfx", "p12", "fullchain", "fritzbox"}
    ):
        chain_content = chain_content or _chain_content(params, signer.cert)
        if key is not None:
            extra_certs = extra_certs or _chain_certificates(params, signer.cert)
    paths: dict[str, str] = {}
    if key is not None:
        changes["pkcs12_changed"], paths = _ensure_pkcs12_exports(
            params, key, cert, extra_certs
        )
    changes["fullchain_changed"] = _ensure_fullchain_bundle(params, cert, chain_content)
    if key is not None:
        changes["fritzbox_bundle_changed"] = _ensure_fritzbox_bundle(
            params, cert, chain_content
        )
    return {**changes, "pkcs12_paths": paths}


def _result(
    params: dict[str, Any],
    changes: dict[str, Any],
    renewal: dict[str, Any],
) -> dict[str, Any]:
    """Combine artifact changes with stable result metadata."""
    return {
        **changes,
        "changed": any(
            value for name, value in changes.items() if name.endswith("_changed")
        ),
        "formats": params["formats"],
        "renewal": renewal,
        "csr_path": params["csr_path"],
        "cert_path": params["cert_path"],
        "txt_path": params["txt_path"],
        "fullchain_path": params.get("fullchain_path", ""),
        "fritzbox_bundle_path": params.get("fritzbox_bundle_path", ""),
    }


def _ensure_x509_from_csr_locked(
    params: dict[str, Any],
    *,
    signed: bool,
    manage_directory: bool,
    manage_chain: bool,
    signer: SignerMaterial,
) -> dict[str, Any]:
    """Ensure one signed certificate from an externally supplied CSR."""
    if not signed:
        raise ValueError("CSR signing requires an issuing CA")
    unsupported = sorted(
        set(params["formats"]).intersection({"pfx", "p12", "fritzbox"})
    )
    if unsupported:
        raise ValueError(
            "CSR signing cannot create formats that require a private key: "
            + ", ".join(unsupported)
        )
    changes = {
        "directory_changed": _directory_change(params, manage_directory),
        "archive_changed": False,
        "key_changed": False,
    }
    existing_cert = _load_existing_certificate(params["cert_path"])
    renewal = _renewal_decision(params, existing_cert)
    renewal["rekey"] = False
    csr, changes["csr_changed"] = _ensure_external_csr(params)
    if signer.key is None:
        signer.key = load_private_key(
            params["signer_key_path"], params["signer_key_passphrase"]
        )
    if signer.cert is None:
        signer.cert = load_certificate(params["signer_cert_path"])
    spec = CertificateSpec(
        csr.public_key(),
        csr.subject,
        _desired_extensions(
            params,
            csr.public_key(),
            signer.cert.public_key(),
            _csr_subject_alt_name(csr),
        ),
    )
    cert, changes["cert_changed"] = _ensure_certificate(
        params, spec, signer, renewal, existing_cert
    )
    changes.update(_ensure_exports(params, cert, signer, None, manage_chain))
    return {
        **_result(params, changes, renewal),
        "csr_mode": True,
        "common_name": _csr_common_name(csr),
        "fritzbox_bundle_path": "",
    }


def _ensure_x509_locked(
    params: dict[str, Any],
    *,
    signed: bool,
    manage_directory: bool,
    manage_chain: bool,
    signer: SignerMaterial | None = None,
) -> dict[str, Any]:
    """Ensure one X.509 object while holding its object lock."""
    signer = signer or SignerMaterial()
    if signed:
        if signer.cert is None:
            signer.cert = load_certificate(params["signer_cert_path"])
        validate_issuer_policies(params, signer.cert)
    if _external_csr_configured(params):
        return _ensure_x509_from_csr_locked(
            params,
            signed=signed,
            manage_directory=manage_directory,
            manage_chain=manage_chain,
            signer=signer,
        )
    changes = {
        "directory_changed": _directory_change(params, manage_directory),
        "archive_changed": False,
    }
    existing_cert = _load_existing_certificate(params["cert_path"])
    renewal = _renewal_decision(params, existing_cert)
    if renewal["rekey"]:
        changes["archive_changed"] = _archive_existing_material(
            params, existing_cert, include_private_key=True
        )
    key, changes["key_changed"] = _ensure_key(
        params, rekey=renewal["rekey"], existing_cert=existing_cert
    )
    subject = subject_from_params(params)
    if signer.key is None:
        signer.key = (
            load_private_key(params["signer_key_path"], params["signer_key_passphrase"])
            if signed
            else key
        )
    extensions = _desired_extensions(
        params,
        key.public_key(),
        signer.cert.public_key() if signer.cert is not None else key.public_key(),
    )
    _csr, changes["csr_changed"] = _ensure_csr(params, key, subject, extensions)
    cert, changes["cert_changed"] = _ensure_certificate(
        params,
        CertificateSpec(key, subject, extensions),
        signer,
        renewal,
        existing_cert,
    )
    changes.update(_ensure_exports(params, cert, signer, key, manage_chain))
    return _result(params, changes, renewal)
