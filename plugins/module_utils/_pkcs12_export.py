# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Content-based reconciliation of private PKCS#12 exports."""

from __future__ import annotations

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificateOperation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    MATERIAL_ERRORS,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    read_file,
    set_attrs,
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._pkcs12_encoding import (
    pkcs12_encryption,
    pkcs12_encryption_matches,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    cert_fingerprint,
    public_key_bytes,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_material import (
    private_key_for,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import (
        PrivateKey,
        PublicKey,
    )
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID
except ImportError:
    pass


def _pkcs12_existing_matches(
    path: str,
    params: CertificateOperation,
    key: PrivateKey | PublicKey,
    cert: x509.Certificate,
    extra_certs: list[x509.Certificate],
) -> bool:
    """Return whether an existing PKCS#12 bundle matches desired content."""
    options = params.request["exports"]
    try:
        content = read_file(path)
    except FileNotFoundError:
        return False
    try:
        existing = pkcs12.load_pkcs12(content, options.passphrase.encode())
        if not pkcs12_encryption_matches(content, options):
            return False
    except MATERIAL_ERRORS:
        return False
    if existing.key is None or existing.cert is None:
        return False
    if (
        existing.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        != public_key_bytes(key)
        or cert_fingerprint(existing.cert.certificate) != cert_fingerprint(cert)
        or existing.cert.friendly_name != friendly_name(params, cert).encode()
    ):
        return False
    existing_fingerprints = sorted(
        cert_fingerprint(item.certificate) for item in existing.additional_certs
    )
    desired_fingerprints = sorted(cert_fingerprint(item) for item in extra_certs)
    return existing_fingerprints == desired_fingerprints


def ensure_pkcs12_exports(
    params: CertificateOperation,
    key: PrivateKey | PublicKey,
    cert: x509.Certificate,
    extra_certs: list[x509.Certificate],
) -> tuple[bool, dict[str, str]]:
    """Ensure requested PKCS#12 export formats exist."""
    paths = params.paths["pkcs12_paths"]
    if not paths:
        return False, {}

    passphrase = params.request["exports"].passphrase
    if not passphrase:
        raise ValueError("PKCS#12 bundle requires pfx_passphrase or passphrase")
    changed = False
    for path in paths.values():
        export_changed = bool(params.request["force"]) or not _pkcs12_existing_matches(
            path,
            params,
            key,
            cert,
            extra_certs,
        )
        if export_changed:
            if params.check_mode:
                changed = True
                continue
            key = private_key_for(params, key)
            content = pkcs12.serialize_key_and_certificates(
                name=friendly_name(params, cert).encode(),
                key=key,
                cert=cert,
                cas=extra_certs,
                encryption_algorithm=pkcs12_encryption(params.request["exports"]),
            )
            changed = (
                write_file(
                    path,
                    content,
                    params.request["storage"].attributes(private=True),
                    check_mode=params.check_mode,
                    force=True,
                )
                or changed
            )
        else:
            changed = (
                set_attrs(
                    path,
                    params.request["storage"].owner,
                    params.request["storage"].group,
                    params.request["storage"].key_mode,
                    check_mode=params.check_mode,
                )
                or changed
            )
    return changed, paths


def friendly_name(params: CertificateOperation, cert: x509.Certificate) -> str:
    """Resolve the explicitly supplied name or the existing CN/object-name default."""
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return params.request["exports"].friendly_name or (
        str(names[0].value) if names else params.request["name"]
    )
