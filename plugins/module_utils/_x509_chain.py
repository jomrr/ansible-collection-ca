# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Internal CA chain discovery shared by issuance and chain exports."""

from __future__ import annotations

from pathlib import Path

from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    MATERIAL_ERRORS,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    load_certificates,
)

try:
    from cryptography import x509
except ImportError:
    pass


def _authority_name(path: Path) -> str:
    """Return the authority short name from a CA certificate path."""
    return path.name[: -len("-ca.pem")]


def _load_authorities(base_dir: str) -> dict[str, x509.Certificate]:
    """Load all CA certificates below the managed CA directory."""
    authorities = {}
    for path in sorted((Path(base_dir.rstrip("/")) / "ca").glob("*-ca.pem")):
        certificates = load_certificates(str(path))
        if certificates:
            authorities[_authority_name(path)] = certificates[0]
    return authorities


def _authority_key_identifier(cert: x509.Certificate) -> bytes | None:
    """Return the certificate Authority Key Identifier when present."""
    try:
        value = cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
    except x509.ExtensionNotFound:
        return None
    return value.key_identifier


def _subject_key_identifier(cert: x509.Certificate) -> bytes | None:
    """Return the certificate Subject Key Identifier when present."""
    try:
        value = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        return None
    return value.digest


def _is_self_signed(cert: x509.Certificate) -> bool:
    """Recognize a self-signed root without truncating self-issued rollover paths."""
    if cert.subject != cert.issuer:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except MATERIAL_ERRORS:
        return False
    return True


def _issuer_matches(
    cert: x509.Certificate,
    candidate: x509.Certificate,
) -> bool:
    """Return whether candidate is the issuer certificate for cert."""
    if candidate.subject != cert.issuer:
        return False
    authority_key = _authority_key_identifier(cert)
    subject_key = _subject_key_identifier(candidate)
    return authority_key is None or subject_key is None or authority_key == subject_key


def _issuer_name(
    cert: x509.Certificate,
    authorities: dict[str, x509.Certificate],
    current_name: str,
) -> str:
    """Return the authority short name that issued cert."""
    matches = [
        name
        for name, candidate in authorities.items()
        if name != current_name and _issuer_matches(cert, candidate)
    ]
    if not matches:
        raise ValueError(
            f"issuer certificate for authority {current_name} was not found"
        )
    if len(matches) > 1:
        names = ", ".join(sorted(matches))
        raise ValueError(
            f"issuer certificate for authority {current_name} is ambiguous: {names}"
        )
    return matches[0]


def _ordered_chain(base_dir: str, name: str) -> list[x509.Certificate]:
    """Return the ordered certificate chain for one CA authority."""
    authorities = _load_authorities(base_dir)
    if name not in authorities:
        raise ValueError(f"authority certificate {name}-ca.pem was not found")

    chain = []
    current_name = name
    seen = set()
    while True:
        if current_name in seen:
            raise ValueError(f"authority chain for {name} contains a loop")
        seen.add(current_name)
        cert = authorities[current_name]
        chain.append(cert)
        if _is_self_signed(cert):
            return chain
        current_name = _issuer_name(cert, authorities, current_name)
