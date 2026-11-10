# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate issuing relationships and derive publication identity before writes."""

from __future__ import annotations

from ansible_collections.jomrr.ca.plugins.module_utils._authority_generations import (
    issuer_urls,
)
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificateOperation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_chain import ordered_chain
from ansible_collections.jomrr.ca.plugins.module_utils._x509_constraints import (
    validate_issuer_constraints,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_extensions import (
    add_extensions,
    desired_extensions,
    subject_from_params,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    load_certificate,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_material import (
    validated_external_csr,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_policies import (
    validate_issuer_policies,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_state import (
    CertificateSpec,
    SignerMaterial,
    SigningRequest,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import PublicKey
    from cryptography import x509
except ImportError:
    pass


def validate_signing_request(
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
        params,
        issuer,
        signer.cert.subject,
        signer.cert.public_key(),
    )
    return csr


def certificate_spec(
    params: CertificateOperation,
    public_key: PublicKey | None,
    signer_public_key: PublicKey | None,
) -> CertificateSpec | None:
    """Validate configuration even when a future key prevents a complete spec."""
    subject = subject_from_params(params)
    if not params.paths["signer_cert_path"] and public_key is not None:
        params.urls = issuer_urls(params, params.request["name"], subject, public_key)
    extensions = desired_extensions(params, public_key, signer_public_key)
    add_extensions(x509.CertificateBuilder().subject_name(subject), extensions)
    if public_key is None:
        return None
    return CertificateSpec(public_key, subject, extensions)


def prepare_signing_request(
    params: CertificateOperation,
    signer: SignerMaterial | None = None,
    *,
    issuer_pending: bool = False,
) -> SigningRequest:
    """Validate once, reusing issuer material for all requests under its lock."""
    signer = signer or SignerMaterial()
    signed = bool(params.paths["signer_cert_path"])
    if signed and params.check_mode and not issuer_pending and signer.cert is None:
        try:
            signer.cert = load_certificate(params.paths["signer_cert_path"])
        except FileNotFoundError:
            issuer_pending = True
    if signed and not issuer_pending:
        csr = validate_signing_request(params, signer)
    else:
        csr = validated_external_csr(params) if params.request["csr"].external else None
    return SigningRequest(signer, csr, issuer_pending)
