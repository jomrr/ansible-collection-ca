# Ansible Collection: jomrr.ca

![GitHub](https://img.shields.io/github/license/jomrr/ansible-collection-ca)
![GitHub last commit](https://img.shields.io/github/last-commit/jomrr/ansible-collection-ca)
![GitHub issues](https://img.shields.io/github/issues-raw/jomrr/ansible-collection-ca)
[![dev](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-collection-ca/dev.yml?branch=dev&label=dev)](https://github.com/jomrr/ansible-collection-ca/actions/workflows/dev.yml?query=branch%3Adev)
[![main](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-collection-ca/main.yml?branch=main&label=main)](https://github.com/jomrr/ansible-collection-ca/actions/workflows/main.yml?query=branch%3Amain)

Manage private certificate authorities, certificates and revocation lists.

## Purpose

Manage a private PKI through independent Ansible modules: root and issuing
authorities, certificate profiles, external CSR signing, renewal, certificate
chains, revocation lists, public artifact archives and FRITZ!Box deployment.

## Requirements

- ansible-core >=2.20.0,<2.21.0

## Installation

```console
ansible-galaxy collection install jomrr.ca
```

## Contents

### Modules

| Name | idempotent | check_mode | Description |
| ---- | ---------- | ---------- | ----------- |
| [`jomrr.ca.authority`](plugins/modules/authority.py) | yes | no | Manage a CA authority certificate |
| [`jomrr.ca.certificate`](plugins/modules/certificate.py) | yes | no | Dispatch one managed CA collection certificate to the built-in X.509 profiles |
| [`jomrr.ca.certificate_batch`](plugins/modules/certificate_batch.py) | yes | no | Dispatch managed CA collection certificates in one batch |
| [`jomrr.ca.chain`](plugins/modules/chain.py) | yes | no | Manage an ordered PEM certificate chain on the managed host |
| [`jomrr.ca.crl`](plugins/modules/crl.py) | yes | no | Manage CA collection certificate revocation lists |
| [`jomrr.ca.fritzbox_deploy`](plugins/modules/fritzbox_deploy.py) | yes | no | Deploy a FritzBox PEM certificate bundle to FRITZ!OS |
| [`jomrr.ca.publish_archive`](plugins/modules/publish_archive.py) | yes | no | Create deterministic public AIA/CDP publish archives on the managed host |

### Documentation Fragments

| Name | idempotent | check_mode | Description |
| ---- | ---------- | ---------- | ----------- |
| [`jomrr.ca.context`](plugins/doc_fragments/context.py) | n/a | n/a | Shared CA file context documentation. |

### Filter Plugins

| Name | idempotent | check_mode | Description |
| ---- | ---------- | ---------- | ----------- |
| [`jomrr.ca.authority_map`](plugins/filter/authority_map.py) | n/a | n/a | Index and validate certificate authorities by name |

## Execution and Requirements

Modules run on the selected managed Linux host, including when delegated
to a dedicated CA host. Install Python 3.12 and `cryptography>=43` in that
host's Ansible interpreter. The controller uses ansible-core 2.20 and
Python 3.12. The `authority_map` filter runs on the controller and needs
no additional Python libraries. No other runtime collections are required.

The modules retain the source role's file layout and certificate profiles.
Check mode skips these state-changing modules without writing files;
diff mode is not implemented. Repeated execution is idempotent unless
renewal is due, requested attributes differ, or `force` is set.

## Authority and Certificate Lifecycle

Create the root authority first, then each issuing authority. Call
`jomrr.ca.chain` for issuing authorities before issuing leaf certificates.
`jomrr.ca.certificate` and `jomrr.ca.certificate_batch` share profiles for
TLS servers and clients, EAP-TLS, identity, MSKDC and FRITZ!Box certificates.
Supply `certificate_types` and `authorities` explicitly; these modules do
not load the standalone role's defaults.

`jomrr.ca.crl` resolves revocations from the persistent inventory by name,
fingerprint or serial. `jomrr.ca.publish_archive` builds a deterministic
archive of public AIA/CDP files. Transfer and web serving are separate tasks.

Keep issuer passphrases and optional PKCS#12 passwords in Ansible Vault.
Renewal and revocation state lives below `base_dir`; preserve this state
together with the CA keys and certificates. FRITZ!Box deployment requires
network access from the managed host and an account allowed to import
certificates. FRITZ!Box uses a self-signed certificate by default, so
`validate_certs` defaults to `false`, as in the source role. Set it to
`true` when the managed host trusts the device certificate.

## Example

```yaml
- name: Create a root authority on the CA host
  hosts: ca
  tasks:
    - name: Create root authority
      jomrr.ca.authority:
        base_dir: /srv/pki/example
        name: root
        common_name: Example Root CA
        days: 3650
        key_passphrase: "{{ vault_root_passphrase }}"
```

Use `ansible-doc jomrr.ca.authority` for parameters and examples. Each
module has its own documentation and can be called without a role.

The complete port of the source role's module and utility documentation
starts at [docs/index.md](docs/index.md). For certificate modules, pass
`owner` and `group` explicitly, as the standalone role does.

## Source

Initially extracted from the MIT-licensed `jomrr.ca` standalone role.
The collection contains modules, their internal utilities and the
`authority_map` filter. It does not embed or modify the standalone role.

## References

- [Collection documentation](https://github.com/jomrr/ansible-collection-ca)

## Author

- Jonas Mauer

## License

License: MIT.
See [LICENSE](LICENSE) for the full license text.

Copyright (c) 2026 Jonas Mauer.
