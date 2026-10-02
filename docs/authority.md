# jomrr.ca.authority

Manage one CA authority certificate.

`jomrr.ca.authority` creates the private key, CSR, PEM certificate, optional DER and
text exports, and CA inventory state for a root or issuing CA.

## Behavior

- `parent` defaults to `name`.
- `parent == name` creates a self-signed root CA.
- `parent != name` creates an issuing CA signed by the parent CA.
- Root CA defaults: `basic_constraints: ["CA:TRUE", "pathlen:1"]`.
- Issuing CA defaults: `basic_constraints: ["CA:TRUE", "pathlen:0"]`.
- Both authority types default `key_usage` to `["keyCertSign", "cRLSign"]`.
- Parent-signed requests validate the complete managed issuer chain's CA status,
  certificate-signing key usage and path length before writing key, CSR or
  certificate material. The requested CA counts as an intermediate so that it
  can subsequently issue usable leaf certificates.
- `Root(pathlen:1) -> Issuing(pathlen:0) -> Leaf` is valid. Adding another CA
  below that issuing CA is rejected. The limit counts depth, not sibling CAs;
  self-issued rollover certificates do not consume a level. Wider or absent
  limits in a child do not override an ancestor's limit.
- The default signature digest is `sha384`; SHA-1 signatures are forbidden.
- Changing the signature digest reissues the certificate and CSR with the
  existing key, unless the signing key fixes its own hash (EdDSA).
- `key_passphrase` is required and is only used in memory by the module.
- `parent_key_passphrase` is required for issuing CAs.
- When reusing a key, only a missing file triggers key generation. An
  unreadable,
  corrupt, or incorrectly encrypted key causes failure without replacing it.
- AIA and CDP URLs are added when `base_url`, `aia_base_url`, or
  `cdp_base_url` are set.
- PEM is always the canonical certificate format. `der` and `txt` add exports.
- Renewal policy can mark warning state, renew inside a configured window, or
  renew at a planned timestamp.
- Renewal keeps the existing key by default. Set `renewal.rekey: true` to
  generate a new private key when renewal is due.
- Replaced generations are archived below `<base_dir>/archive/authorities`.

## Parameters

- **`base_dir`**: Base directory for CA artifacts.
  Type: path; Required: yes; Default: none; Allowed values: any absolute or
  relative path; Secret: no

- **`base_url`**: Base publication URL. If set, AIA defaults to
  `<base_url>/aia/<parent>-ca.der` and CDP to `<base_url>/crl/<parent>-ca.crl`;
  a root references itself.
  Type: str; Required: no; Default: `""`; Allowed values: any URL prefix;
  Secret: no

- **`ca_name`**: Enables composed inventory output when non-empty.
  Type: str; Required: no; Default: `""`; Allowed values: any string; Secret: no

- **`name`**: Authority short name.
  Type: str; Required: yes; Default: none; Allowed values: safe filename stem;
  Secret: no

- **`parent`**: Parent CA name. Same as `name` means self-signed root.
  Type: str; Required: no; Default: `""`, treated as `name`; Allowed values:
  existing authority name; Secret: no

- **`formats`**: Output formats for the CA certificate.
  Type: list[str]; Required: no; Default: `["pem", "der", "txt"]`; Allowed
  values: `pem`, `der`, `txt`; Secret: no

- **`key_type`**: Private key algorithm.
  Type: str; Required: no; Default: `RSA`; Allowed values: see
  [index](index.md#common-value-sets); Secret: no

- **`key_size`**: Key size or ECDSA curve selector. Ignored for Ed25519 and
  Ed448.
  Type: int; Required: no; Default: `4096`; Allowed values: RSA bit size, or
  `256`/`384` for generic ECDSA; Secret: no

- **`key_passphrase`**: Passphrase for the generated authority private key.
  Type: str; Required: yes; Default: none; Allowed values: any string; Secret:
  yes

- **`parent_key_passphrase`**: Parent CA private key passphrase for issuing CAs.
  Type: str; Required: conditional; Default: none; Allowed values: any string;
  Secret: yes

- **`subject_ordered`**: Full ordered subject override. Takes precedence over
  `subject`, `common_name`, and `email`.
  Type: list[dict]; Required: no; Default: `[]`; Allowed values: supported
  subject keys; Secret: no

- **`common_name`**: Common Name. Required unless `subject_ordered` is set.
  Type: str; Required: conditional; Default: none; Allowed values: any string;
  Secret: no

- **`email`**: Optional subject `emailAddress`.
  Type: str; Required: no; Default: none; Allowed values: email address; Secret:
  no

- **`subject`**: Subject defaults used with `common_name`.
  Type: dict; Required: no; Default: `{}`; Allowed values: supported subject
  keys; Secret: no

- **`basic_constraints`**: Basic Constraints tokens.
  Type: list[str]; Required: no; Default: root or issuing default; Allowed
  values: `CA:TRUE`, `CA:FALSE`, `pathlen:<n>`; Secret: no

- **`key_usage`**: Key Usage tokens.
  Type: list[str]; Required: no; Default: `["keyCertSign", "cRLSign"]`; Allowed
  values: see below; Secret: no

- **`key_usage_critical`**: Marks Key Usage critical.
  Type: bool; Required: no; Default: `true`; Allowed values: `true`, `false`;
  Secret: no

- **`extended_key_usage`**: Extended Key Usage values. Usually empty for CAs.
  Type: list[str]; Required: no; Default: `[]`; Allowed values: EKU names or
  dotted OIDs; Secret: no

- **`extended_key_usage_critical`**: Marks Extended Key Usage critical.
  Type: bool; Required: no; Default: `false`; Allowed values: `true`, `false`;
  Secret: no

- **`san`**: Subject Alternative Name entries.
  Type: list[str]; Required: no; Default: `[]`; Allowed values: supported SAN
  syntax; Secret: no

- **`san_critical`**: Marks SAN critical.
  Type: bool; Required: no; Default: `false`; Allowed values: `true`, `false`;
  Secret: no

- **`aia_base_url`**: Explicit AIA URL prefix. The module appends
  `<parent>-ca.der` (the root name for a root).
  Type: str; Required: no; Default: `""`; Allowed values: any URL prefix;
  Secret: no

- **`cdp_base_url`**: Explicit CDP URL prefix. The module appends
  `<parent>-ca.crl` (the root name for a root).
  Type: str; Required: no; Default: `""`; Allowed values: any URL prefix;
  Secret: no

- **`raw_extensions`**: Additional unrecognized extensions.
  Type: list[dict]; Required: no; Default: `[]`; Allowed values: supported raw
  extension syntax; Secret: no

- **`pkinit`**: Internal PKINIT context for SAN otherName encoding.
  Type: dict; Required: no; Default: `{}`; Allowed values: internal PKINIT
  shape; Secret: no

- **`days`**: Certificate validity in days.
  Type: int; Required: yes; Default: none; Allowed values: positive integer;
  Secret: no

- **`renewal`**: Renewal and rekey policy.
  Type: dict; Required: no; Default: `{}`; Allowed values: see below; Secret: no

- **`digest`**: Signature digest for RSA and ECDSA keys.
  Type: str; Required: no; Default: `sha384`; Allowed values: `sha224`, `sha256`,
  `sha384`, `sha512`; Secret: no

- **`include_identifiers`**: Adds SKI and AKI extensions.
  Type: bool; Required: no; Default: `true`; Allowed values: `true`, `false`;
  Secret: no

- **`owner`**: Owner for generated files.
  Type: str; Required: no; Default: none; Allowed values: user name or UID;
  Secret: no

- **`group`**: Group for generated files.
  Type: str; Required: no; Default: none; Allowed values: group name or GID;
  Secret: no

- **`key_mode`**: Private key file mode.
  Type: str; Required: no; Default: `0600`; Allowed values: octal mode string;
  Secret: no

- **`public_mode`**: CSR, certificate, DER, text, and inventory file mode.
  Type: str; Required: no; Default: `0644`; Allowed values: octal mode string;
  Secret: no

- **`force`**: Regenerates managed material even if current files match.
  Type: bool; Required: no; Default: `false`; Allowed values: `true`, `false`;
  Secret: no

Supported Key Usage values are `digitalSignature`, `nonRepudiation`,
`contentCommitment`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`,
`keyCertSign`, `cRLSign`, `encipherOnly`, and `decipherOnly`.

### Renewal Policy

- **`warn_before_days`**: Adds warning state to inventory when remaining
  validity is inside this window.
  Type: int; Default: `0`

- **`renew_before_days`**: Renews when remaining validity is inside this window.
  Type: int; Default: `7`

- **`renew_at`**: Planned renewal timestamp as ISO-8601 or `YYYYMMDDHHMMSSZ`. It
  only affects certificates issued before that timestamp.
  Type: str; Default: `""`

- **`rekey`**: Generates a new private key when renewal is due.
  Type: bool; Default: `false`

## Generated Files

For `name: root` and `base_dir: /etc/pki/example`:

- `/etc/pki/example/private/root-ca.key`
- `/etc/pki/example/csr/root-ca.csr`
- `/etc/pki/example/ca/root-ca.pem`
- `/etc/pki/example/ca/root-ca.der` when `der` is requested
- `/etc/pki/example/ca/root-ca.txt` when `txt` is requested
- `/etc/pki/example/inventory/state/authorities/root.json`
- `/etc/pki/example/inventory/state/authority_certificates/root/<serial>.json`
- `/etc/pki/example/inventory/ca-inventory.json` when `ca_name` is set
- `/etc/pki/example/archive/authorities/root/<serial>/*` for replaced
  generations

`jomrr.ca.authority` does not create chain files. Chain generation is handled by
[`jomrr.ca.chain`](chain.md).

## Return Values

- **`changed`**: Whether any generated artifact or inventory state changed.
  Type: bool

- **`directory_changed`**: Always `false` for authorities.
  Type: bool

- **`key_changed`**: Whether the private key changed.
  Type: bool

- **`csr_changed`**: Whether the CSR changed.
  Type: bool

- **`cert_changed`**: Whether the PEM certificate changed.
  Type: bool

- **`der_changed`**: Whether the DER export changed.
  Type: bool

- **`txt_changed`**: Whether the text export changed.
  Type: bool

- **`chain_changed`**: Always `false` for authorities.
  Type: bool

- **`archive_changed`**: Whether replaced generation material was archived.
  Type: bool

- **`inventory_changed`**: Whether CA inventory state changed.
  Type: bool

- **`formats`**: Normalized certificate formats.
  Type: list[str]

- **`renewal`**: Renewal decision for this run.
  Type: dict

- **`csr_path`**: CSR path.
  Type: str

- **`cert_path`**: PEM certificate path.
  Type: str

- **`txt_path`**: Text export path, or empty string.
  Type: str

## Examples

Create a self-signed root CA:

```yaml
- name: Create root CA
  jomrr.ca.authority:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    name: root
    parent: root
    common_name: Example Root CA
    subject:
      country: DE
      organization: Example
      organizational_unit: Example PKI
    days: 3650
    key_passphrase: "{{ ca_root_passphrase }}"
```

Create an issuing CA signed by the root CA:

```yaml
- name: Create component CA
  jomrr.ca.authority:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    name: component
    parent: root
    common_name: Example Component CA
    subject:
      country: DE
      organization: Example
      organizational_unit: Example PKI
    days: 1825
    key_passphrase: "{{ ca_component_passphrase }}"
    parent_key_passphrase: "{{ ca_root_passphrase }}"
    renewal:
      renew_before_days: 30
      rekey: true
```

## CA key rollover and publication

The first signing generation keeps `<name>-ca.der` and `<name>-ca.crl`, preserving
URLs already embedded in certificates. A new key (or changed issuer subject)
gets `<name>-ca-<generation_id>.der` and `<name>-ca-<generation_id>.crl`.
The ID is SHA-256 over the DER subject followed by DER SubjectPublicKeyInfo;
renewing a certificate with the same key and subject keeps its generation ID.
Explicit AIA/CDP base URL prefixes still apply.

`authority` keeps public issuer material under
`<base_dir>/generations/<name>/<generation_id>/` and pins the first identity in
`generations/<name>/legacy.json`. Current signing material remains under `ca/`
and `private/`; replaced keys remain in `archive/authorities/<name>/<serial>/`.

After the renewal task above, run these tasks before deploying new certificates:

```yaml
- name: Refresh the current component CA chain
  jomrr.ca.chain:
    base_dir: /etc/pki/example
    name: component

- name: Refresh CRLs for all component CA generations
  jomrr.ca.crl:
    base_dir: /etc/pki/example
    name: component
    common_name: Example Component CA
    key_passphrase: "{{ ca_component_passphrase }}"
    next_update_days: 30
    revoked_certificates: "{{ ca_revocations.component | default([]) }}"

- name: Package all retained generations for publication
  jomrr.ca.publish_archive:
    base_dir: /etc/pki/example
    dest: /tmp/example-public.tar
    authorities: "{{ ca_authorities }}"
```

Create or refresh CRLs for the other listed authorities as well, then transfer
and unpack the archive on the publication hosts. Continue running CRL and
publication tasks for old generations while their certificates are in use.
Every CRL uses its generation's subject, AKI and signing key. All generations
carry the logical authority's complete revocation list, one monotonic CRL number
and matching `thisUpdate` times. Old CRLs cap `nextUpdate` at retirement.
A new signing key does not reset the counter.

### Archive passphrases and retirement

Keep archived keys, their passphrases, public generation material and inventory
state together in backups. When passphrases change, supply the old values through
`crl.archived_key_passphrases`; IDs are returned under `generations`:

```yaml
archived_key_passphrases:
  "{{ old_generation_id }}": "{{ vaulted_old_ca_passphrase }}"
```

IDs without an override use the current `key_passphrase`. Missing or unreadable
keys for an **active** generation stop CRL preparation before any CRL or
revocation-state update.

`crl` reports `generations[id].retire_at` and `generations[id].retired`. An old
generation stops signing when the last recorded certificate issued by that key
expires, and no later than the old CA certificate expiry. This includes managed
subordinate CAs and CA certificates issued from external CSRs. If historical
certificates cannot be attributed reliably, or history is absent, the CA expiry
is used conservatively. Preserve complete issuance inventory; old summaries
without AKI are resolved against their current or archived certificate files.
The current CA remains active until it is replaced as the signer.

The final old CRL's `nextUpdate` is capped at its retirement deadline. It is not
regenerated repeatedly just because this final deadline enters the usual renewal
window. After retirement the module does not load or decrypt that generation's
private key. The operator can destroy the archived key and remove its passphrase;
keys are never deleted automatically. Keep public generation records, the last
CRL and the persistent counter. Publication includes retained CA certificates and
any existing final CRLs without requiring a retired private key.

### Recover an earlier rollover

Existing `archive/authorities/<name>/<serial>/<name>-ca.pem` and `.key` material
is reused; a previous rollover does not require recreating the CA. Run `crl`
first to adopt the archived generations, restore their CRL service and retain
their public certificates, then publish with `authorities`. The legacy URL owner
is inferred from recorded AIA/CDP references or an unambiguous oldest CA
certificate. The existing CRL sequence continues even if the old path was
previously overwritten by a CRL signed with the new key.

If multiple generations already used the same legacy URLs, automatic selection
fails with candidate generation IDs and certificate serials. Explicitly choose
which generation keeps those URLs:

```yaml
- name: Recover CRL service after an earlier CA rollover
  jomrr.ca.crl:
    base_dir: /etc/pki/example
    name: component
    common_name: Example Component CA
    key_passphrase: "{{ ca_component_passphrase }}"
    archived_key_passphrases: "{{ ca_archived_key_passphrases }}"
    legacy_generation: "{{ original_generation_id }}"
    next_update_days: 30
  register: recovered_crls
```

The owner is then pinned. `migration_conflicts` lists unexpired, unrevoked
certificates whose embedded legacy URLs point at a different generation. Reissue
these certificates with `certificate`, `certificate_batch` or `authority`, deploy
the replacements and revoke the superseded serials. New certificates reference
their generation's suffixed URLs automatically. Both generations' correctly
signed CRLs and AIA certificates are published throughout this migration.
Existing conflicting URLs cannot themselves be changed by restoring an archive.

## Certificate policies

- `certificate_policies`: list of `{oid, cps_uri?}` entries, default `[]`.
- `policy_constraints`: dictionary, default `{}`. Optional nonnegative
  `require_explicit_policy` and `inhibit_policy_mapping` counters.
- `inhibit_any_policy`: optional nonnegative integer.

Constraint counters of `0` activate immediately; omitted values emit no
constraint. Both constraint extensions are critical; policies are noncritical.

Policy-bearing issuers require every end certificate to declare a nonempty
subset
of the OIDs in the actual issuer certificate. CPS URLs need not match. Policies
are explicit: they are neither inherited nor inferred from profiles or external
CSRs. An empty issuer list accepts only certificates without policies.

Constraints require a nonempty sub-CA policy list. Roots and end certificates
cannot carry constraints through this module. `anyPolicy` is supported only on
self-signed roots; root policy lists do not restrict sub-CA issuance. The policy
extension OIDs, including unsupported policyMappings, cannot be passed through
`raw_extensions`. User Notices are not supported.

Policy reordering is idempotent. Changed policy OIDs, CPS URLs, or constraints
reissue the certificate using the existing key unless renewal requests rekeying.
See the [source role README](https://github.com/jomrr/ansible-role-ca/blob/0e59800e7528dbe2ad8eeaaf962a849f25d0bd92/README.md) for the original PKI example and client validation limits.
