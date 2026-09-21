# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

X.509 exports helpers."""

from __future__ import annotations

from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    MATERIAL_ERRORS,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    FileAttributes,
    read_file,
    set_attrs,
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    _cert_fingerprint,
    _public_key_bytes,
    load_certificates,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import PrivateKey
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
except ImportError:
    pass


def _ensure_der(params: dict[str, Any], cert: x509.Certificate) -> bool:
    """Ensure the optional DER certificate export exists."""
    if not params["der_path"]:
        return False
    return write_file(
        params["der_path"],
        cert.public_bytes(serialization.Encoding.DER),
        FileAttributes.from_params(params),
    )


def _ensure_chain(params: dict[str, Any]) -> bool:
    """Ensure the optional certificate chain copy exists."""
    if not params["chain_src_path"] or not params["chain_path"]:
        return False
    content = read_file(params["chain_src_path"])
    return write_file(
        params["chain_path"],
        content,
        FileAttributes.from_params(params),
    )


def _chain_content(
    params: dict[str, Any], signer_cert: x509.Certificate | None
) -> bytes:
    """Return the issuing chain content for certificate export bundles."""
    for path in (params.get("chain_src_path"), params.get("chain_path")):
        if not path:
            continue
        try:
            return read_file(path).rstrip() + b"\n"
        except FileNotFoundError:
            continue
    if signer_cert is not None:
        return signer_cert.public_bytes(serialization.Encoding.PEM).rstrip() + b"\n"
    raise ValueError("certificate chain is required for bundle export formats")


def _chain_certificates(
    params: dict[str, Any], signer_cert: x509.Certificate | None
) -> list[x509.Certificate]:
    """Return issuing chain certificates for PKCS#12 exports."""
    for path in (params.get("chain_src_path"), params.get("chain_path")):
        if not path:
            continue
        try:
            return load_certificates(path)
        except FileNotFoundError:
            continue
    return [signer_cert] if signer_cert is not None else []


def _pkcs12_existing_matches(
    path: str,
    passphrase: str | None,
    key: PrivateKey,
    cert: x509.Certificate,
    extra_certs: list[x509.Certificate],
) -> bool:
    """Return whether an existing PKCS#12 bundle matches desired content."""
    try:
        existing_key, existing_cert, existing_extra = pkcs12.load_key_and_certificates(
            read_file(path),
            passphrase.encode() if passphrase else None,
        )
    except MATERIAL_ERRORS:
        return False
    if existing_key is None or existing_cert is None:
        return False
    if existing_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != _public_key_bytes(key):
        return False
    if _cert_fingerprint(existing_cert) != _cert_fingerprint(cert):
        return False
    existing_fingerprints = sorted(
        _cert_fingerprint(item) for item in (existing_extra or [])
    )
    desired_fingerprints = sorted(_cert_fingerprint(item) for item in extra_certs)
    return existing_fingerprints == desired_fingerprints


def _pkcs12_passphrase(params: dict[str, Any]) -> str:
    """Return the configured PKCS#12 passphrase."""
    return str(params.get("passphrase") or params.get("pfx_passphrase") or "")


def _ensure_pkcs12_exports(
    params: dict[str, Any],
    key: PrivateKey,
    cert: x509.Certificate,
    extra_certs: list[x509.Certificate],
) -> tuple[bool, dict[str, str]]:
    """Ensure requested PKCS#12 export formats exist."""
    paths = {
        export_format: params["pkcs12_paths"][export_format]
        for export_format in ("pfx", "p12")
        if export_format in params["formats"]
    }
    if not paths:
        return False, {}

    passphrase = _pkcs12_passphrase(params)
    if not passphrase:
        raise ValueError("PKCS#12 bundle requires pfx_passphrase or passphrase")
    friendly_name = str(
        params.get("friendly_name") or params.get("common_name") or params["name"]
    )
    content = pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode(),
        key=key,
        cert=cert,
        cas=extra_certs,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
    )

    changed = False
    for path in paths.values():
        export_changed = bool(params["force"]) or not _pkcs12_existing_matches(
            path,
            passphrase,
            key,
            cert,
            extra_certs,
        )
        if export_changed:
            changed = (
                write_file(
                    path,
                    content,
                    FileAttributes.from_params(params, "key_mode"),
                    force=True,
                )
                or changed
            )
        else:
            changed = (
                set_attrs(path, params["owner"], params["group"], params["key_mode"])
                or changed
            )
    return changed, paths


def _pem_join(*parts: bytes) -> bytes:
    """Join PEM sections with exactly one trailing newline per section."""
    return b"".join(part.rstrip() + b"\n" for part in parts if part)


def _ensure_fullchain_bundle(
    params: dict[str, Any], cert: x509.Certificate, chain_content: bytes
) -> bool:
    """Ensure the requested PEM fullchain bundle exists."""
    if "fullchain" not in params["formats"]:
        return False
    content = _pem_join(cert.public_bytes(serialization.Encoding.PEM), chain_content)
    return write_file(
        params["fullchain_path"],
        content,
        FileAttributes.from_params(params),
        force=params["force"],
    )


def _ensure_fritzbox_bundle(
    params: dict[str, Any], cert: x509.Certificate, chain_content: bytes
) -> bool:
    """Ensure the requested FritzBox PEM import bundle exists."""
    if "fritzbox" not in params["formats"]:
        return False
    content = _pem_join(
        cert.public_bytes(serialization.Encoding.PEM),
        chain_content,
        read_file(params["key_path"]),
    )
    return write_file(
        params["fritzbox_bundle_path"],
        content,
        FileAttributes.from_params(params, "key_mode"),
        force=params["force"],
    )
