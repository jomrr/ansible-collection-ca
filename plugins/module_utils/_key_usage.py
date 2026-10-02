# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Internal X.509 Key Usage mapping for construction, inventory and text exports."""

from __future__ import annotations

from collections.abc import Iterable

try:
    from cryptography import x509
except ImportError:
    pass


KEY_USAGES = (
    ("digital_signature", "digitalSignature", "Digital Signature"),
    ("content_commitment", "nonRepudiation", "Non Repudiation"),
    ("key_encipherment", "keyEncipherment", "Key Encipherment"),
    ("data_encipherment", "dataEncipherment", "Data Encipherment"),
    ("key_agreement", "keyAgreement", "Key Agreement"),
    ("key_cert_sign", "keyCertSign", "Certificate Sign"),
    ("crl_sign", "cRLSign", "CRL Sign"),
    ("encipher_only", "encipherOnly", "Encipher Only"),
    ("decipher_only", "decipherOnly", "Decipher Only"),
)
AGREEMENT_ONLY = {"encipher_only", "decipher_only"}


def key_usage(values: Iterable[str] | None) -> x509.KeyUsage:
    """Build Key Usage, accepting both names for content commitment."""
    names = {str(value) for value in values or []}
    if "contentCommitment" in names:
        names.add("nonRepudiation")
    flags = {
        attribute: token in names
        and (attribute not in AGREEMENT_ONLY or "keyAgreement" in names)
        for attribute, token, _label in KEY_USAGES
    }
    return x509.KeyUsage(**flags)


def key_usage_names(value: x509.KeyUsage, *, readable: bool = False) -> list[str]:
    """Return enabled usages in stable order without reading undefined attributes."""
    return [
        label if readable else token
        for attribute, token, label in KEY_USAGES
        if (attribute not in AGREEMENT_ONLY or value.key_agreement)
        and getattr(value, attribute)
    ]
