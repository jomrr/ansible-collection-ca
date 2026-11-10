# jomrr.ca.authority_batch

Manage a complete authority graph and its chains in one managed-host module
invocation. The standalone role uses this module for its `ca_authorities` phase.
The individual [`authority`](authority.md) and [`chain`](chain.md) modules remain
available and share the same implementation.

## Inputs

- `base_dir`: Required CA working directory.
- `authorities`: Required list of authority definitions. Each entry requires
  `name`, `parent`, `days` and a non-empty `key_passphrase`. Set `parent` equal
  to `name` for a self-signed root. A common name or ordered subject is required
  by the authority engine, as with the single module.
- `base_url`, `ca_name`: Publication and composed inventory context; default `""`.
- `subject`, `renewal`: Shared defaults, each defaulting to `{}`. Per-authority
  mappings override matching keys while retaining other shared fields.
- `owner`, `group`: Optional ownership for authority material and chains.
- `force`: Force authority regeneration and chain writes; default `false`.

Authority cryptographic fields use the single module's defaults, including RSA
4096, SHA-384, private mode `0600` and public mode `0644`. Authority definitions
may also retain certificate/CRL metadata used by the role's other phases.
Parent key passphrases always come from the matching authority in this list.
Chain exports use PEM, DER and text with mode `0644`, matching the role's
individual chain calls. `ansible-doc jomrr.ca.authority_batch` lists all fields.

## Execution

The whole graph is validated before writes, including duplicate names, missing
parents and cycles. Input order need not follow the graph. For each authority,
the module manages its material, updates inventory, then manages its chain.
Root chain files are absent because they would duplicate the root certificate.
An empty list succeeds unchanged without creating CA state.

The batch holds the graph lock once and shares its authority locks with the
issuance and chain operations. Single-module operations retain their normal
locking. Renewal, issuer constraints, retained generations and file permissions
use the same engines as individual operations. A failure stops execution;
completed authorities remain managed and are reconciled on the next run.

Check mode predicts material, inventory and chain changes without writes or key
generation. Parent changes propagate to dependent certificates and chains.
Missing issuers are treated as pending creation; validation of their future
constraints is deferred. Diff mode is unsupported. Nested
credential fields are redacted by Ansible. The role also sets `no_log: true`.

## Result

`changed` combines material, inventory and chain changes. `count` reports the
processed authorities; `inventory_changed` reports their inventory changes.
`results` follows parent-first execution order and contains each authority's
`name`, `changed`, `cert_path`, `csr_path`, `chain_paths`, `chain_changed` and
`inventory_changed`. It contains no credentials.

```yaml
- name: Manage CA authorities and chains
  become: true
  become_user: root
  jomrr.ca.authority_batch:
    base_dir: /etc/pki/example
    base_url: http://pki.example.test
    ca_name: example
    authorities: "{{ ca_authorities }}"
    subject: "{{ ca_subject }}"
    renewal: "{{ ca_renewal }}"
    owner: root
    group: root
  no_log: true
```
