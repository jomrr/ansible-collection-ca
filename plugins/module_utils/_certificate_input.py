# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Normalize module input into the typed certificate request."""

from __future__ import annotations

from collections.abc import Mapping

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificatePolicy,
    CertificateRequest,
    CsrSource,
    ExportOptions,
    Extensions,
    IssuerOptions,
    KeyOptions,
    NameExtensions,
    PolicyExtensions,
    Publication,
    RawExtension,
    Storage,
    Subject,
    UsageExtensions,
)
from ansible_collections.jomrr.ca.plugins.module_utils._formats import normalize_formats
from ansible_collections.jomrr.ca.plugins.module_utils._input import (
    InputValues,
    mapping,
)
from ansible_collections.jomrr.ca.plugins.module_utils._renewal import renewal_policy
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    digest_algorithm,
)


def _extensions(values: InputValues) -> Extensions:
    raw: list[RawExtension] = []
    for item in values.sequence("raw_extensions"):
        extension = InputValues(mapping(item, "raw_extensions"))
        raw.append(
            {
                "oid": extension.text("oid"),
                "value": extension.text("value"),
                "critical": extension.boolean("critical"),
            }
        )
    policies: list[CertificatePolicy] = []
    for item in values.sequence("certificate_policies"):
        policy = InputValues(mapping(item, "certificate_policies"))
        entry: CertificatePolicy = {"oid": policy.text("oid")}
        if "cps_uri" in policy.values:
            entry["cps_uri"] = policy.text("cps_uri")
        policies.append(entry)
    constraints = InputValues(values.dictionary("policy_constraints"))
    return Extensions(
        basic_constraints=values.strings("basic_constraints"),
        usage=UsageExtensions(
            values.strings("key_usage"),
            values.boolean("key_usage_critical", True),
            values.strings("extended_key_usage"),
            values.boolean("extended_key_usage_critical"),
        ),
        names=NameExtensions(
            values.strings("san"),
            values.boolean("san_critical"),
            InputValues(values.dictionary("pkinit")).text("realm"),
        ),
        policies=PolicyExtensions(
            policies,
            {name: constraints.integer(name) for name in constraints.values},
            values.integer("inhibit_any_policy")
            if values.values.get("inhibit_any_policy") is not None
            else None,
        ),
        raw=raw,
        include_identifiers=values.boolean("include_identifiers", True),
    )


def certificate_request(
    params: Mapping[str, object], *, authority: bool
) -> CertificateRequest:
    """Validate resolved profile input before it enters the issuance engine."""
    values = InputValues(params)
    subject_ordered = []
    for item in values.sequence("subject_ordered"):
        entry = mapping(item, "subject_ordered")
        subject_ordered.append({key: InputValues(entry).text(key) for key in entry})
    return CertificateRequest(
        name=values.text("name"),
        days=values.integer("days"),
        digest=digest_algorithm(values.text("digest")).name,
        force=values.boolean("force"),
        authority=authority,
        profile=values.text("profile"),
        storage=Storage(
            values.text("base_dir").rstrip("/"),
            values.text("owner") or None,
            values.text("group") or None,
            values.text("key_mode", "0600"),
            values.text("public_mode", "0644"),
            values.text("directory_mode", "0755"),
        ),
        publication=Publication(
            values.text("base_url"),
            values.text("aia_base_url"),
            values.text("cdp_base_url"),
        ),
        subject=Subject(
            values.text("common_name"),
            values.text("email"),
            subject_ordered,
            values.text_mapping("subject"),
        ),
        extensions=_extensions(values),
        key=KeyOptions(
            values.text("key_type", "RSA"),
            values.integer("key_size", 4096),
            values.text("key_passphrase") or None,
        ),
        csr=CsrSource(values.text("csr_source_path"), values.text("csr_content")),
        exports=ExportOptions(
            normalize_formats(params.get("formats")),
            values.text("output_dir"),
            values.text("friendly_name"),
            values.text("passphrase") or values.text("pfx_passphrase"),
        ),
        issuer=IssuerOptions(
            values.text("parent" if authority else "issuer"),
            values.text("signer_key_passphrase") or None,
        ),
        renewal=renewal_policy(params.get("renewal")),
    )
