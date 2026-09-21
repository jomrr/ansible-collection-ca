# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Certificate requests and shared issuer material for X.509 operations."""

from __future__ import annotations

from dataclasses import dataclass, field

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import (
        PrivateKey,
        PublicKey,
    )
    from cryptography import x509
except ImportError:
    pass


@dataclass
class SignerMaterial:
    """Issuer key, certificate and optional cached bundle material."""

    key: PrivateKey | None = None
    cert: x509.Certificate | None = None
    chain_content: bytes = b""
    extra_certs: list[x509.Certificate] = field(default_factory=list)


@dataclass
class CertificateSpec:
    """Subject, key and extensions requested for one certificate."""

    key: PrivateKey | PublicKey
    subject: x509.Name
    extensions: list[tuple[x509.ObjectIdentifier, bool, x509.ExtensionType]]
