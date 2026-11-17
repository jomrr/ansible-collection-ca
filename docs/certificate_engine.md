# ca_certificate_engine

Internal shared implementation for certificate dispatcher modules.

This helper is not a user-facing Ansible module. It exists so
`jomrr.ca.certificate` and `jomrr.ca.certificate_batch` resolve certificate models, apply
profile defaults, create artifacts, and update inventory through one code path.

## Collection-internal Helper Functions

- **`single_certificate_argument_spec()`**
  Behavior: Returns the Ansible argument spec for `jomrr.ca.certificate`.

- **`batch_certificate_argument_spec()`**
  Behavior: Returns the Ansible argument spec for `jomrr.ca.certificate_batch`.

- **`prepare_certificate_artifacts(params, certificate=None, authorities=None)`**
  Behavior: Resolves one declarative certificate into typed input, artifact paths
  and public inventory metadata. Batches reuse the validated authority map.

- **`ensure_certificate_artifacts(params, certificate=None)`**
  Behavior: Ensures one certificate and updates inventory state.

- **`ensure_certificate_batch(params)`**
  Behavior: Ensures all certificates in `params["certificates"]`, writes
  certificate inventory fragments, and composes inventory once.

## Defaults And Validation

Profile defaults come from `ca_profiles`:

- standard certificates and MSKDC: `pem`, `der`, `txt`
- issuing CA certificates: `pem`, `der`, `txt`, `fullchain`
- identity certificates: `pem`, `der`, `txt`, `pfx`
- FritzBox certificates: `pem`, `der`, `txt`, `fritzbox`

PKCS#12 exports additionally require `asn1crypto>=1.5.1,<2` on the managed host.
Their `pfx_encryption`, `pfx_iterations` and `pfx_friendly_name` settings are
documented in [certificate.md](certificate.md#pkcs12-encryption).

Supported export formats are `pem`, `der`, `cer`, `txt`, `pfx`, `p12`, `fullchain`,
`bundle`, and `fritzbox`. The optional `cer` format writes the same DER certificate bytes
as `der`, using a `.cer` extension; defaults remain unchanged.

Certificate models that set `csr_path` or `csr_content` are treated as
CSR-signed certificates. They require an approved `common_name` or
`subject_ordered`, reject `pfx`, `p12`, `bundle`, and `fritzbox`, and copy the verified CSR
to the managed CSR path. Only its public key is used for issuance: the subject
and SANs come from task parameters and profile defaults, never from the CSR.

The `issuing_ca` profile defaults to `CA:TRUE`, `pathlen:0`, `keyCertSign` and
`cRLSign`, without EKU or SAN defaults. Basic Constraints are resolved before
the root-issuer check, so a managed root can sign the request. The complete
managed chain still enforces CA constraints before any certificate material is
written. Explicit extension overrides retain their existing behavior.

The helper validates certificate type, issuer existence, required profile
fields, PFX passphrase requirements, merged subject defaults, renewal policy
overrides, and MSKDC Kerberos realm propagation before calling the X.509 helper.

Normal and check-mode batches use the same prepared operations and issuer grouping.
Each external CSR is validated once and the signing key is loaded once per issuer
while that issuer's locks are held.
