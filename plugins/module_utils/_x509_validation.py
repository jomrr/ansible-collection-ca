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
from ansible_collections.jomrr.ca.plugins.module_utils._x509_material import (
    validated_external_csr,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_policies import (
    validate_issuer_policies,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_state import (
    CertificateSpec,
    SignerMaterial,
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
