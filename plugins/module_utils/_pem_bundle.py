# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Private PEM bundle exports, including the unchanged FRITZ!Box representation."""

from __future__ import annotations

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificateOperation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    read_file,
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    PEM_CERT_RE,
    private_key_pem,
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
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass


def join_pem(*parts: bytes) -> bytes:
    """Join PEM sections with exactly one trailing newline per section."""
    return b"".join(part.rstrip() + b"\n" for part in parts if part)


def _matches_format(content: bytes, key_format: str) -> bool:
    """Recognize the PKCS#8 or algorithm-specific PEM envelope."""
    headers = (
        (b"PRIVATE KEY", b"ENCRYPTED PRIVATE KEY")
        if key_format == "pkcs8"
        else (b"RSA PRIVATE KEY", b"EC PRIVATE KEY")
    )
    return any(
        content.startswith(b"-----BEGIN " + header + b"-----") for header in headers
    )


def _existing_key(
    params: CertificateOperation, key: PrivateKey | PublicKey
) -> bytes | None:
    """Reuse a converted key's bytes to keep encrypted exports idempotent."""
    try:
        content = read_file(params.paths["bundle_path"])
    except FileNotFoundError:
        return None
    # Accept both legacy key-last bundles and keys directly behind the leaf.
    content = PEM_CERT_RE.sub(b"", content).strip()
    if not _matches_format(content, params.request["exports"].bundle_key_format):
        return None
    passphrase = params.request["key"].passphrase
    try:
        existing = serialization.load_pem_private_key(
            content, password=passphrase.encode() if passphrase else None
        )
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None
    if existing.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != public_key_bytes(key):
        return None
    return content


def ensure_key_bundle(
    params: CertificateOperation,
    key: PrivateKey | PublicKey,
    certificate: bytes,
    chain: bytes,
    *,
    fritzbox: bool = False,
) -> bool:
    """Write PKCS#8 key after leaf; traditional and FRITZ!Box keep key last."""
    path = params.paths["fritzbox_bundle_path" if fritzbox else "bundle_path"]
    if not path:
        return False
    key_content = read_file(params.paths["key_path"])
    key_format = params.request["exports"].bundle_key_format
    # FRITZ!Box always retains the original managed key bytes, including encryption.
    if not fritzbox and not _matches_format(key_content, key_format):
        existing = _existing_key(params, key)
        if existing is None:
            if params.check_mode:
                return True
            key_content = private_key_pem(
                private_key_for(params, key),
                params.request["key"].passphrase,
                key_format=key_format,
            )
        else:
            key_content = existing
    parts = (
        (certificate, chain, key_content)
        if fritzbox or key_format == "traditional"
        else (certificate, key_content, chain)
    )
    return write_file(
        path,
        join_pem(*parts),
        params.request["storage"].attributes(private=True),
        check_mode=params.check_mode,
        force=params.request["force"],
    )
