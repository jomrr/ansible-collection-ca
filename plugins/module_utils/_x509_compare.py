# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared comparison rules for issuance and check-mode predictions."""

from __future__ import annotations

from ansible_collections.jomrr.ca.plugins.module_utils._x509_extensions import (
    extensions_equal,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    as_public_key,
    cert_public_key_bytes,
    csr_public_key_bytes,
    public_key_bytes,
    signature_algorithm_oid,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_state import (
    CertificateSpec,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import PublicKey
    from cryptography import x509
except ImportError:
    pass


def csr_matches(
    existing: x509.CertificateSigningRequest, spec: CertificateSpec, digest: str
) -> bool:
    """Compare a CSR with the requested subject, key, signature and extensions."""
    return (
        existing.subject == spec.subject
        and existing.signature_algorithm_oid
        == signature_algorithm_oid(as_public_key(spec.key), digest)
        and csr_public_key_bytes(existing) == public_key_bytes(spec.key)
        and extensions_equal(existing.extensions, spec.extensions)
    )


def certificate_matches(
    existing: x509.Certificate,
    spec: CertificateSpec,
    issuer: x509.Name,
    signing_key: PublicKey,
    digest: str,
) -> bool:
    """Compare certificate fields independently of renewal windows and writes."""
    return (
        existing.subject == spec.subject
        and existing.issuer == issuer
        and existing.signature_algorithm_oid
        == signature_algorithm_oid(signing_key, digest)
        and cert_public_key_bytes(existing) == public_key_bytes(spec.key)
        and extensions_equal(existing.extensions, spec.extensions)
    )
