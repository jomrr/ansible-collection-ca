# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Typed certificate input and derived state, internal to the collection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NotRequired, TypedDict

from ansible_collections.jomrr.ca.plugins.module_utils._file import FileAttributes


class RenewalPolicy(TypedDict):
    """Normalized renewal configuration, distinct from a run's decision."""

    warn_before_days: int
    renew_before_days: int
    renew_at: str
    rekey: bool


class RenewalDecision(TypedDict):
    """Serializable decision for a single observed certificate."""

    renew: bool
    rekey: bool
    reason: str
    warning: bool
    days_remaining: int | None
    policy: RenewalPolicy


class RawExtension(TypedDict):
    """Validated raw extension input."""

    oid: str
    value: str
    critical: bool


class CertificatePolicy(TypedDict):
    """Certificate policy OID and optional CPS URL."""

    oid: str
    cps_uri: NotRequired[str]


@dataclass
class Storage:
    """CA storage root and permissions, without private material."""

    base_dir: str
    owner: str | None
    group: str | None
    key_mode: str
    public_mode: str
    directory_mode: str

    def attributes(self, *, private: bool = False) -> FileAttributes:
        """Return file attributes for an export's confidentiality level."""
        return FileAttributes(
            self.owner, self.group, self.key_mode if private else self.public_mode
        )


@dataclass
class Subject:
    """Approved subject input, independent of externally supplied CSR subjects."""

    common_name: str
    email: str
    ordered: list[dict[str, str]]
    values: dict[str, str]


@dataclass
class KeyOptions:
    """Managed private-key settings; passwords are excluded from repr."""

    key_type: str
    key_size: int
    passphrase: str | None = field(repr=False)


@dataclass
class CsrSource:
    """Optional external request, mutually exclusive path and content."""

    path: str
    content: str

    @property
    def external(self) -> bool:
        """Whether issuance uses an externally managed key."""
        return bool(self.path or self.content)


@dataclass
class ExportOptions:
    """Requested representations and PKCS#12 settings."""

    formats: list[str]
    output_dir: str
    friendly_name: str
    passphrase: str = field(repr=False)


@dataclass
class IssuerOptions:
    """Resolved issuer and its credential, separate from observed signing material."""

    name: str
    passphrase: str | None = field(repr=False)


@dataclass
class Publication:
    """Configured publication bases; generation URLs are derived separately."""

    base_url: str
    aia_base_url: str
    cdp_base_url: str

    def url(self, filename: str, *, aia: bool) -> str:
        """Resolve an explicit publication base or the common base URL."""
        base = (self.aia_base_url if aia else self.cdp_base_url).rstrip("/")
        if not base and self.base_url:
            base = self.base_url.rstrip("/") + ("/aia" if aia else "/crl")
        return f"{base}/{filename}" if base else ""


@dataclass
class IssuerUrls:
    """Public endpoints derived from the actual locked signing identity."""

    aia: str = ""
    cdp: str = ""


@dataclass
class UsageExtensions:
    """Key Usage and Extended Key Usage settings."""

    key_usage: list[str]
    key_usage_critical: bool
    extended_key_usage: list[str]
    extended_key_usage_critical: bool


@dataclass
class NameExtensions:
    """Subject alternative identities and PKINIT encoding context."""

    san: list[str]
    san_critical: bool
    pkinit_realm: str


@dataclass
class PolicyExtensions:
    """Policy OIDs and inherited policy constraints."""

    values: list[CertificatePolicy]
    constraints: dict[str, int]
    inhibit_any_policy: int | None


@dataclass
class Extensions:
    """Validated extension configuration, excluding derived issuer URLs."""

    basic_constraints: list[str]
    usage: UsageExtensions
    names: NameExtensions
    policies: PolicyExtensions
    raw: list[RawExtension]
    include_identifiers: bool


class CertificatePaths(TypedDict):
    """Derived artifact locations; empty strings denote unrequested exports."""

    lock_path: str
    key_path: str
    csr_path: str
    cert_path: str
    der_path: str
    txt_path: str
    directory_path: str
    signer_lock_path: str
    signer_cert_path: str
    signer_key_path: str
    chain_src_path: str
    chain_path: str
    fullchain_path: str
    fritzbox_bundle_path: str
    pkcs12_paths: dict[str, str]


class CertificateRequest(TypedDict):
    """Required, normalized issuance input; contains no derived or observed state."""

    name: str
    storage: Storage
    subject: Subject
    key: KeyOptions
    csr: CsrSource
    exports: ExportOptions
    issuer: IssuerOptions
    publication: Publication
    extensions: Extensions
    renewal: RenewalPolicy
    days: int
    digest: str
    force: bool
    authority: bool
    profile: str


@dataclass
class CertificateOperation:
    """Input and derived state with explicitly separate owners."""

    request: CertificateRequest
    paths: CertificatePaths
    urls: IssuerUrls = field(default_factory=IssuerUrls)
