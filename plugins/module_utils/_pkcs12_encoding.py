# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""PKCS#12 encryption selection and inspection through public library APIs."""

from __future__ import annotations

from collections.abc import Callable

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    ExportOptions,
)

ASN1CRYPTO_IMPORT_ERROR: str | None
try:
    from asn1crypto import algos
    from asn1crypto import pkcs12 as asn1_pkcs12
except ImportError as exc:
    ASN1CRYPTO_IMPORT_ERROR = str(exc)
else:
    ASN1CRYPTO_IMPORT_ERROR = None

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
except ImportError:
    pass


def require_pkcs12_parser() -> None:
    """Report a missing managed-host dependency before modifying CA material."""
    if ASN1CRYPTO_IMPORT_ERROR is not None:
        raise ValueError(
            "PKCS#12 exports require asn1crypto>=1.5.1 on the managed host: "
            + ASN1CRYPTO_IMPORT_ERROR
        )


def pkcs12_encryption(
    options: ExportOptions,
) -> serialization.KeySerializationEncryption:
    """Keep the existing best default and offer explicit legacy-device encryption."""
    password = options.passphrase.encode()
    if options.pfx_encryption == "best" and options.pfx_iterations is None:
        return serialization.BestAvailableEncryption(password)
    builder = serialization.PrivateFormat.PKCS12.encryption_builder()
    if options.pfx_encryption == "compatibility2022":
        builder = builder.key_cert_algorithm(
            pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC
        ).hmac_hash(hashes.SHA1())
    if options.pfx_iterations is not None:
        builder = builder.kdf_rounds(options.pfx_iterations)
    return builder.build(password)


def _algorithm_matches(
    algorithm: algos.EncryptionAlgorithm, options: ExportOptions
) -> bool:
    """Compare the cipher/KDF and optional rounds, ignoring randomized salt and IV."""
    if options.pfx_encryption == "compatibility2022":
        matches = algorithm["algorithm"].native == "pkcs12_sha1_tripledes_3key"
    else:
        matches = (
            algorithm["algorithm"].native == "pbes2"
            and algorithm["parameters"]["encryption_scheme"]["algorithm"].native
            == "aes256_cbc"
            and algorithm["parameters"]["key_derivation_func"]["algorithm"].native
            == "pbkdf2"
            and algorithm["parameters"]["key_derivation_func"]["parameters"]["prf"][
                "algorithm"
            ].native
            == "sha256"
        )
    return bool(
        matches
        and (
            options.pfx_iterations is None
            or algorithm.kdf_iterations == options.pfx_iterations
        )
    )


def pkcs12_encryption_matches(content: bytes, options: ExportOptions) -> bool:
    """Inspect the actual MAC and both encrypted certificate and key containers."""
    require_pkcs12_parser()
    load_pfx: Callable[..., asn1_pkcs12.Pfx] = asn1_pkcs12.Pfx.load
    load_bags: Callable[..., asn1_pkcs12.SafeContents] = asn1_pkcs12.SafeContents.load
    pfx = load_pfx(content, strict=True)
    mac = "sha1" if options.pfx_encryption == "compatibility2022" else "sha256"
    if pfx["mac_data"]["mac"]["digest_algorithm"]["algorithm"].native != mac:
        return False
    encrypted_certificates = False
    encrypted_key = False
    for item in pfx.authenticated_safe:
        kind = item["content_type"].native
        if kind == "encrypted_data":
            algorithm = item["content"]["encrypted_content_info"][
                "content_encryption_algorithm"
            ]
            if not _algorithm_matches(algorithm, options):
                return False
            encrypted_certificates = True
        elif kind == "data":
            for bag in load_bags(item["content"].native):
                if bag["bag_id"].native != "pkcs8_shrouded_key_bag":
                    return False
                if not _algorithm_matches(
                    bag["bag_value"]["encryption_algorithm"], options
                ):
                    return False
                encrypted_key = True
        else:
            return False
    return encrypted_certificates and encrypted_key
