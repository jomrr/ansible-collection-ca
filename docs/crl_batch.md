# jomrr.ca.crl_batch

Manage CRLs for existing authorities in one invocation, independently of authority
issuance. Each authority uses the same engine, generation handling and locks as
[`jomrr.ca.crl`](crl.md). The standalone role is not changed by this addition.

## Inputs

Pass the usual `authorities` list and `base_dir`. Each selected authority requires
`name`, `key_passphrase` and positive `crl_days`. Other authority fields are
accepted, so the list can be shared with authority and certificate modules.

| CRL input | Authority field or batch input |
| --- | --- |
| `next_update_days` | Required authority `crl_days` |
| `renew_before_days` | Authority `crl_renew_before_days`, else batch `renew_before_days` (default 7) |
| `digest` | Authority `crl_digest`, default `sha384` |
| `revoked_certificates` | Batch `revocations[name]`, default `[]` |

Renewal windows may be fractional or zero and must be smaller than the CRL
lifetime. `archived_key_passphrases` and `legacy_generation` retain their
single-module meanings. Nested passwords are protected by Ansible `no_log`.
The batch accepts `base_url`, `ca_name`, `owner`, `group` and `force` with the
single-module defaults. It writes PEM and DER CRLs with mode `0644`.

## Execution and result

Authorities are processed in input order. Each operation holds that authority's
Authority-Lock and CRL-Lock, then releases them before the next authority.
No authority certificates, keys or chains are created or renewed.

Duplicate names, invalid renewal windows and malformed revocation lists fail
before the first write. An operational failure stops execution; completed
authorities remain managed. An empty list succeeds unchanged without CA writes.
Recorded revocations persist even after declarations are removed. Entries in
`revocations` for authorities outside the batch are ignored.

`changed` and `inventory_changed` combine all results; `count` reports the number
of authorities. `results` contains each authority's `name` plus the full `crl`
result, including paths, sequence number, generations and migration conflicts.
Migration warnings identify the affected authority. Check mode skips without
writes; diff mode is unsupported, as with the individual module.

```yaml
- name: Renew revocation lists after updating revocations
  jomrr.ca.crl_batch:
    base_dir: /srv/pki/example
    authorities: "{{ ca_authorities }}"
    revocations: "{{ ca_revocations }}"
    renew_before_days: "{{ ca_crl_renew_before_days }}"
    owner: root
    group: root
  tags: ca_crl
  no_log: true
```
