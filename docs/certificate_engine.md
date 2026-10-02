# ca_certificate_engine

Internal shared implementation for certificate dispatcher modules.

This helper is not a user-facing Ansible module. It exists so
`jomrr.ca.certificate` and `jomrr.ca.certificate_batch` resolve certificate models, apply
profile defaults, create artifacts, and update inventory through one code path.

## Public Helper Functions

- **`single_certificate_argument_spec()`**
  Behavior: Returns the Ansible argument spec for `jomrr.ca.certificate`.

- **`batch_certificate_argument_spec()`**
  Behavior: Returns the Ansible argument spec for `jomrr.ca.certificate_batch`.

- **`prepare_certificate_artifacts(params, certificate=None)`**
  Behavior: Resolves one declarative certificate model into X.509 helper
  parameters.

- **`ensure_certificate_artifacts(params, certificate=None)`**
  Behavior: Ensures one certificate and updates inventory state.

- **`ensure_certificate_batch(params)`**
  Behavior: Ensures all certificates in `params["certificates"]`, writes
  certificate inventory fragments, and composes inventory once.

## Defaults And Validation

Profile defaults come from `ca_profiles`:

- standard certificates and MSKDC: `pem`, `der`, `txt`
- identity certificates: `pem`, `der`, `txt`, `pfx`
- FritzBox certificates: `pem`, `der`, `txt`, `fritzbox`

Supported export formats are `pem`, `der`, `txt`, `pfx`, `p12`, `fullchain`,
and `fritzbox`.

Certificate models that set `csr_path` or `csr_content` are treated as
CSR-signed certificates. They require an approved `common_name` or
`subject_ordered`, reject `pfx`, `p12`, and `fritzbox`, and copy the verified CSR
to the managed CSR path. Only its public key is used for issuance: the subject
and SANs come from task parameters and profile defaults, never from the CSR.

The helper validates certificate type, issuer existence, required profile
fields, PFX passphrase requirements, merged subject defaults, renewal policy
overrides, and MSKDC Kerberos realm propagation before calling the X.509 helper.
