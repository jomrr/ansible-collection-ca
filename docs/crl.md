# jomrr.ca.crl

Manage certificate revocation lists for all signing generations of one CA.

`jomrr.ca.crl` creates PEM and DER exports for each active CA signing generation
and records CRL and revocation state in the internal CA inventory.

Serial parsing and timestamp normalization are delegated to the internal
`ca_serial` and `ca_time` helpers.

## Behavior

- Reads the current CA private key from `<base_dir>/private/<name>-ca.key` and
  matching old keys from `archive/authorities/<name>/<serial>/`.
- Signs and renews CRLs for every active issuer generation. The original
  generation keeps its unsuffixed path; later ones use
  `<base_dir>/crl/<name>-ca-<generation_id>.crl` (DER) and `.crl.pem` (PEM).
- All generations contain the same complete authority revocation list and share
  a monotonic counter and `thisUpdate`; each has its own issuer, AKI and signature.
- Generation IDs and paths are returned in `generations`. `paths` points to the
  current generation, which can have a suffix after rollover.
- Preparation validates every required signing key before writing CRLs or
  revocation state; missing keys or wrong passphrases fail instead of skipping
  an active generation.
- Old generations retire at the last issued certificate expiry, bounded by CA
  expiry. Uncertain or absent history falls back to CA expiry. The current signer
  remains active. Retired keys are no longer decrypted and may be destroyed by
  the operator; keys are not deleted automatically.
- `generations[id].retire_at` and `.retired` report this lifecycle. Final CRLs stop
  at that deadline and remain on disk without being re-signed.
- Earlier rollovers are recovered from the existing CA archive. Use
  `legacy_generation` only when the original URL owner cannot be inferred;
  `migration_conflicts` identifies certificates needing reissuance or revocation.
- See [CA rollover and publication](authority.md#ca-key-rollover-and-publication)
  for retained material, publication order and migration limitations.
- Uses the complete subject of each generation's CA certificate as its CRL issuer,
  preserving email addresses, attribute order and repeated attributes.
- Replaces existing CRLs whose issuer differs from the CA subject, incrementing
  the persisted CRL number. Repeated runs with a matching CRL remain unchanged.
- Defaults to writing both `pem` and `der` CRL formats when `formats` is not
  supplied.
- Writes the original generation's PEM CRL to `<base_dir>/crl/<name>-ca.crl.pem`.
- Writes the original generation's DER CRL to `<base_dir>/crl/<name>-ca.crl`.
- PEM and DER are exports of the same generated CRL object, so they share CRL
  Number, AKI, `lastUpdate`, `nextUpdate`, and revoked entries.
- Rewrites the CRL when the issuer, digest, next update, or revoked serial list
  differs, when CRL Number or AKI is missing or inconsistent, when the existing
  CRL enters its renewal window, or when `force: true` is set.
- CRLs renew seven days before nextUpdate by default. `renew_before_days` may be
  fractional, must be nonnegative, and must be less than `next_update_days`.
- CRL sequence numbers are persisted before export in
  `inventory/state/crl_numbers/<name>.json`, independently of PEM and DER
  exports. Corrupt counter state fails instead of resetting the sequence.
- The default signature digest is `sha384`; SHA-1 signatures are forbidden.
- Adds CRL Number and Authority Key Identifier extensions.
- Supports CRL Reason and Invalidity Date revoked-certificate extensions.
- Resolves revocations by certificate name or fingerprint through CA inventory
  state, including managed CA certificates. Revoke a subordinate CA in its
  parent's CRL: module `name: root`, entry `name: issuer`.
- Name selection considers current leaf and CA certificates issued by the CRL
  authority. If both share a name under that issuer, use a fingerprint or serial.
  Fingerprints also select historical certificates after renewal or rekey.
- Revocation events are recorded by issuer and serial before exporting the CRL.
  They remain in later CRLs even when their declarations are removed.
- For leaves and CAs alike, a name selector binds to its first revoked generation.
  A reissued certificate is not automatically revoked; select its serial or
  fingerprint to revoke it.
- An omitted revocation date retains the first recorded revocation time.
- Recorded `key_compromise` and `ca_compromise` events prevent issuance with the
  same public key of a known local certificate, even under another name or serial.
  Recovery requires a new key; see [compromised keys and renewal](certificate.md#compromised-keys-and-renewal).
  Record the revocation with this module before issuing replacements.

## Parameters

At role level, users normally declare revocations with `ca_revocations`, keyed
by issuing authority name. The role passes `ca_revocations[<authority>]` to this
module as `revoked_certificates`.

- **`base_dir`**: Base CA directory.
  Type: path; Required: yes; Default: none; Allowed values: any absolute or
  relative path; Secret: no

- **`base_url`**: A non-empty value updates composed inventory when `ca_name` is
  set. Omitted or empty values preserve the stored URL.
  Type: str; Required: no; Default: `""`; Allowed values: any URL prefix;
  Secret: no

- **`ca_name`**: Enables composed inventory output when non-empty.
  Type: str; Required: no; Default: `""`; Allowed values: any string; Secret: no

- **`name`**: CA authority short name.
  Type: str; Required: yes; Default: none; Allowed values: authority name;
  Secret: no

- **`formats`**: CRL output formats written from one generated CRL object.
  Type: list[str]; Required: no; Default: `["pem", "der"]`; Allowed values:
  `pem`, `der`; Secret: no

- **`key_passphrase`**: Passphrase for the CA private key.
  Type: str; Required: yes; Default: none; Allowed values: any string; Secret:
  yes

- **`archived_key_passphrases`**: Optional mapping `{generation_id: passphrase}`
  for old keys encrypted with a different passphrase. Missing entries fall back
  to `key_passphrase`; all values are secret. IDs are in the `generations` return
  value and the directories below `generations/<name>/`.
  Type: dict; Required: no; Default: `{}`; Secret: yes

- **`legacy_generation`**: Optional generation ID to own the original unsuffixed
  URLs during archive migration. If inference is ambiguous, the error lists
  candidate IDs and CA certificate serials. Once pinned, the owner cannot be
  changed through this option.
  Type: str; Required: no; Default: `""`; Secret: no

- **`common_name`**: Accepted for compatibility. The issuer Common Name is taken
  from the CA certificate; this parameter does not override it.
  Type: str; Required: yes; Default: none; Allowed values: any string; Secret:
  no

- **`subject`**: Accepted for compatibility. The full issuer subject is taken
  from the CA certificate; this parameter does not override it.
  Type: dict; Required: no; Default: `{}`; Allowed values: supported subject
  keys; Secret: no

- **`next_update_days`**: Number of days until CRL `nextUpdate`.
  Type: int; Required: yes; Default: none; Allowed values: positive integer;
  Secret: no

- **`renew_before_days`**: Renew before expiry; role default is
  `ca_crl_renew_before_days`, with per-authority `crl_renew_before_days`
  overrides.
  Type: float; Required: no; Default: `7`; Allowed values: nonnegative, less
  than `next_update_days`; Secret: no

- **`revoked_certificates`**: Declarative revoked certificate entries.
  Type: list[dict]; Required: no; Default: `[]`; Allowed values: see below;
  Secret: no

- **`digest`**: Signature digest for RSA and ECDSA CA keys.
  Type: str; Required: no; Default: `sha384`; Allowed values: `sha224`, `sha256`,
  `sha384`, `sha512`; Secret: no

- **`owner`**: Owner for the CRL and inventory files.
  Type: str; Required: no; Default: none; Allowed values: user name or UID;
  Secret: no

- **`group`**: Group for the CRL and inventory files.
  Type: str; Required: no; Default: none; Allowed values: group name or GID;
  Secret: no

- **`mode`**: CRL file mode.
  Type: str; Required: no; Default: `0644`; Allowed values: octal mode string;
  Secret: no

- **`force`**: Rewrites the CRL even if current content matches.
  Type: bool; Required: no; Default: `false`; Allowed values: `true`, `false`;
  Secret: no

Each `revoked_certificates` item accepts one certificate selector:

- **`name`**: Current leaf or CA certificate name resolved through CA inventory.
  Type: str; Required: conditional; Default: none; Allowed values: managed
  certificate name

- **`certificate_name`**: Alias for `name`.
  Type: str; Required: conditional; Default: none; Allowed values: managed
  certificate name

- **`certificate`**: Alias for `name`.
  Type: str; Required: conditional; Default: none; Allowed values: managed
  certificate name

- **`fingerprint`**: Current or historical leaf or CA certificate fingerprint
  resolved through CA inventory.
  Type: str; Required: conditional; Default: none; Allowed values: SHA-1 or
  SHA-256 hex, optionally prefixed with `sha1:` or `sha256:`

- **`sha1`**: SHA-1 certificate fingerprint.
  Type: str; Required: conditional; Default: none; Allowed values: SHA-1 hex

- **`sha256`**: SHA-256 certificate fingerprint.
  Type: str; Required: conditional; Default: none; Allowed values: SHA-256 hex

- **`serial`**: Certificate serial number.
  Type: int/str; Required: conditional; Default: none; Allowed values: decimal,
  `0x` hex, or colon-separated hex

- **`serial_number`**: Certificate serial number.
  Type: int/str; Required: conditional; Default: none; Allowed values: decimal,
  `0x` hex, or colon-separated hex

Each item also accepts:

- **`revocation_date`**: Revocation timestamp.
  Type: str; Required: no; Default: current UTC time; Allowed values: ISO-8601
  or `YYYYMMDDHHMMSSZ`

- **`reason`**: CRL reason extension.
  Type: str; Required: no; Default: none; Allowed values: see reason list

- **`invalidity_date`**: Invalidity Date extension.
  Type: str; Required: no; Default: none; Allowed values: ISO-8601 or
  `YYYYMMDDHHMMSSZ`

Supported revocation reasons:

- `key_compromise`
- `ca_compromise`
- `affiliation_changed`
- `superseded`
- `cessation_of_operation`
- `certificate_hold`
- `privilege_withdrawn`
- `aa_compromise`

## Generated Files

For `name: component` and `base_dir: /etc/pki/example`:

- `/etc/pki/example/crl/component-ca.crl.pem` when `pem` is requested
- `/etc/pki/example/crl/component-ca.crl` when `der` is requested
- `/etc/pki/example/inventory/state/crls/component/<format>.json`
- `/etc/pki/example/inventory/state/crl_numbers/component.json`
- `/etc/pki/example/inventory/state/revocations/component/<serial>.json`
- `/etc/pki/example/inventory/ca-inventory.json` when `ca_name` is set

## Return Values

| Name | Type | Description |
| --- | --- | --- |
| `changed` | bool | Whether the CRL or inventory state changed. |
| `inventory_changed` | bool | Whether inventory state changed. |
| `formats` | list[str] | Written formats. |
| `paths` | dict | Output paths keyed by format. |
| `crl_number` | int | CRL Number extension value. |

## Examples

Create a PEM CRL:

```yaml
- name: Create component CA CRL
  jomrr.ca.crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    common_name: Example Component CA
    subject:
      country: DE
      organization: Example
      organizational_unit: Example PKI
    next_update_days: 7
    renew_before_days: 1
    key_passphrase: "{{ ca_component_passphrase }}"
```

Create default PEM and DER CRLs with one revoked certificate by name:

```yaml
- name: Create component CA CRLs
  jomrr.ca.crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    common_name: Example Component CA
    next_update_days: 7
    renew_before_days: 1
    key_passphrase: "{{ ca_component_passphrase }}"
    revoked_certificates:
      - name: web01
        reason: key_compromise
        invalidity_date: "2026-06-14T00:00:00Z"
```

Revoke by SHA-256 fingerprint:

```yaml
- name: Create component CA CRLs with fingerprint revocation
  jomrr.ca.crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    common_name: Example Component CA
    next_update_days: 7
    renew_before_days: 1
    key_passphrase: "{{ ca_component_passphrase }}"
    revoked_certificates:
      - sha256: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        reason: superseded
```

CRL numbering follows [RFC 5280 section 5.2.3](https://www.rfc-editor.org/rfc/rfc5280.html#section-5.2.3):
the sequence remains monotonic for the logical issuer and scope across key changes.

Revoke a managed issuing CA in the Root CA's CRL:

```yaml
- name: Revoke issuing CA ffw
  jomrr.ca.crl:
    base_dir: /etc/pki/example
    name: root
    common_name: Example Root CA
    key_passphrase: "{{ ca_root_passphrase }}"
    next_update_days: 30
    revoked_certificates:
      - name: ffw
        reason: ca_compromise
```

To select a specific CA certificate after renewal or rekey, replace `name: ffw`
with `sha256: "<fingerprint of that CA certificate>"`. The fingerprint identifies
the certificate, not its public key. The parent must match the CRL's `name`.
Previously recorded name selectors continue to identify the initially revoked
certificate; they do not revoke its replacement automatically.

## Selecting archived signing keys

A generation is identified by its CA subject and public key. The module selects
its current or archived certificate/key pair using the public certificate before
it decrypts a key. It prefers the current pair, then archived pairs in sorted
serial-directory order; a missing key may fall back to another pair of the same
generation. Each active generation decrypts one selected key, including when
unrelated archived keys are invalid or encrypted with different passwords.

Missing pairs, denied file access, malformed certificates, key mismatch and
private-key decryption/parsing failures are reported separately. A bad password
and corrupt encrypted key bytes cannot always be distinguished by the crypto
backend; the error identifies the key path and generation to investigate.
