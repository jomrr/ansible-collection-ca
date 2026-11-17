# jomrr.ca.artifacts

Build a file manifest from the same definitions passed to the issuance modules:

```yaml
ca_files: "{{ ca_certificates | jomrr.ca.artifacts(ca_authorities) }}"
```

The filter runs on the controller without reading the CA filesystem. It returns
one entry per configured current file, sorted by `src`:

```yaml
- src: certs/web01/web01-fullchain.pem
  owner: web01
  format: fullchain
  secret: false
```

`src` is relative to the modules' `base_dir`. `owner` is the certificate or
authority name, not a filesystem user. Join `base_dir` and `src` in the task that
reads or transfers the file on the CA host.

## File selection

| Definition | Listed files |
| --- | --- |
| Authority | PEM plus requested DER, CER and TXT exports. Default: PEM, DER, TXT. |
| Certificate | PEM and chain, plus requested public formats. Omitted `formats` uses the certificate profile's defaults. |
| Certificate with `publish_private: true` | Also its local key and requested bundle, FRITZ!Box and PKCS#12 exports. |

Duplicate formats produce one entry. Explicit `formats: []` lists only mandatory
files: PEM for an authority, PEM and chain for a certificate. Directly root-signed
certificates have an empty chain file. The filter does not list CSR files, CRLs,
CA chain exports or archived generations, nor files left over from earlier format
selections. It assumes successful issuance with the supplied definitions.

Definitions must use the default layout. A non-empty `output_dir` raises a filter
error: the filter has no `base_dir` argument with which to derive a relative path
for custom directories. Use the issuance module's returned paths for those cases.

## Private material

`publish_private` is a certificate boolean, default `false`. Set it for devices
whose private material an administrator handles manually:

```yaml
ca_certificates:
  - name: scanner
    type: tls_server
    common_name: scanner.example.test
    formats: [cer, pfx]
    pfx_passphrase: "{{ vault_scanner_pfx_passphrase }}"
    publish_private: true
```

This lists `scanner.pem`, `scanner-chain.pem`, `scanner.cer`, `scanner.key` and
`scanner.pfx` under `certs/scanner/`. The key and PFX entries have `secret: true`.
The option only controls the manifest: it neither creates extra exports nor
publishes files, changes issuance or renews the certificate. CA keys are never
listed. External CSR definitions have no local private key to list.

Private formats include `key`, `bundle`, `pfx` and the existing `fritzbox` and `p12`
aliases. Alias entries retain their format name and actual filename
(`-fritzbox.pem` or `.p12`). All require `publish_private: true`; `key` is added
automatically for local-key certificates and is not an accepted `formats` option.

Consumers can select public files explicitly:

```yaml
ca_public_files: >-
  {{ ca_certificates | jomrr.ca.artifacts(ca_authorities) |
     rejectattr('secret') | list }}
```
