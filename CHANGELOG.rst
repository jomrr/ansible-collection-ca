==========================
jomrr.ca 1.1 Release Notes
==========================

.. contents:: Topics

v1.1.1
======

Bugfixes
--------

- Preserve the last non-empty base_url in composed inventory when modules omit the parameter or pass an empty string, avoiding changed results when alternating authority, certificate, certificate_batch and crl tasks.
- certificate and certificate_batch - avoid automatic leaf Extended Key Usage and common-name DNS SAN defaults when issuing certificates with CA:TRUE, including external CA CSRs signed with tls_server or tls_client profiles.
- certificate and certificate_batch - honor explicitly empty extended_key_usage and san lists, allowing certificates without EKU or automatic DNS SAN while preserving omitted leaf profile defaults and required mskdc PKINIT SANs.
- crl - stop requiring the ignored common_name parameter. The CRL issuer comes entirely from the CA certificate. Both common_name and subject remain accepted as optional, ignored compatibility parameters; omit them in new tasks.

v1.1.0
======

Minor Changes
-------------

- Certificate inventory records include a SHA-256 public key fingerprint to retain compromised-key identity across generations; older records use current or archived certificates.
- Consolidate internal artifact paths, inventory certificate lookup, Key Usage mapping, file mode parsing and format validation while preserving module interfaces and output formats.
- certificate and certificate_batch - add the issuing_ca profile for signing external issuing CA CSRs with a managed root, with CA constraints, signing key usages and fullchain export defaults.
- crl - expose generation lifetimes and accept archived_key_passphrases for keys with different passphrases.
- crl - support legacy_generation selection and report migration_conflicts when earlier rollovers reused issuer URLs.

Breaking Changes / Porting Guide
--------------------------------

- External CSR tasks must define common_name or subject_ordered and explicitly supply approved SANs. Omitted or empty SANs no longer import identities from the CSR; normal profile defaults apply.

Security Fixes
--------------

- certificate and certificate_batch - stop inheriting external CSR subject attributes and SANs; use task-approved identities and profile defaults after verifying the CSR signature.
- certificate, certificate_batch and authority - reject reuse of locally known keys revoked for key_compromise or ca_compromise, including renewal and external CSRs. Replacement requires a new key; certificate names and serial numbers do not bypass the check.

Bugfixes
--------

- authority - retain issuer generations and pin legacy AIA/CDP URLs across CA rekey.
- authority, certificate, certificate_batch - reject issuance that exceeds path length limits anywhere in the managed CA chain before writing certificate material.
- certificate and certificate_batch - mask nested secrets without redacting public certificate names, formats, issuer groups or returned paths.
- certificate and certificate_batch - preserve nested secret masking in invocation logs and complete results with newer Ansible versions.
- certificate and certificate_batch - protect nested passphrases during Ansible argument validation, check-mode skips and invocation logging.
- certificate, certificate_batch - permit a root to sign explicitly requested external CA certificates when the issuer chain permits the additional CA level.
- crl - recover generations from existing CA archives and retire old CRLs at issued certificate or CA expiry.
- crl - reject ambiguous names shared by a leaf and CA under the same issuer instead of selecting one silently.
- crl - resolve managed CA certificates by name and fingerprint in their parent's CRL, including historical CA certificates by fingerprint.
- crl - reuse one authority-history snapshot and legacy URL resolution per run, including migration; derive publication paths and select signing keys without rereading CA certificates.
- crl - sign CRLs with each active generation key and preserve monotonic CRL numbers across rollover.
- crl - use the CA certificate subject for CRL issuance and comparison, preserving email addresses and ordered subject attributes; replace existing CRLs with mismatched issuers.
- publish_archive - include retained issuer certificates and their matching active or final CRLs.
- publish_archive - reuse the loaded authority history and resolved legacy URL owner for every published generation.

v1.0.1
======

Bugfixes
--------

- Embed module and filter documentation in Python files to prevent duplicate Galaxy entries.
- Exclude documentation source and build directories from the Galaxy package.
- Share module documentation through Python fragments and run Pylint serially so local and CI duplicate checks use the same files.

v1.0.0
======

Minor Changes
-------------

- Initial extraction of the CA role modules and authority map filter with collection-qualified imports.
