# jomrr.ca.host_certificates

Build certificate definitions from a list of short inventory host
names. The filter runs on the controller without additional Python dependencies.

```yaml
ca_certificates: >-
  {{ groups['webservers'] | jomrr.ca.host_certificates(hostvars, 'example.test') }}
```

Each selected host must have an `ansible_host` containing an IPv4 or IPv6 address.
The filter does not resolve DNS names. Missing hosts, missing addresses and
non-IP addresses produce a filter error. Only selected hosts are inspected.

Given `hosts: [web02, web01]` and these host variables:

```yaml
web01:
  ansible_host: 192.0.2.10
web02:
  ansible_host: 2001:db8::20
```

The result is sorted by `name`:

```yaml
- name: web01
  type: tls_server
  common_name: web01.example.test
  key_type: P-384
  san: [DNS:web01.example.test, DNS:web01, 'IP:192.0.2.10']
  formats: [pem, der, txt, fullchain]
- name: web02
  type: tls_server
  common_name: web02.example.test
  key_type: P-384
  san: [DNS:web02.example.test, DNS:web02, 'IP:2001:db8::20']
  formats: [pem, der, txt, fullchain]
```

Signature:

```jinja
hosts | jomrr.ca.host_certificates(hostvars, domain=None,
                                 key_type='P-384',
                                 formats=['pem', 'der', 'txt', 'fullchain'],
                                 fqdn_var='fqdn',
                                 overrides_var='ca_certificate')
```

Without host-specific variables, `domain` is appended with a dot to each input
host name and the type is `tls_server`. `key_type` and `formats` provide the
defaults for every host. The certificate modules validate supported types, key
types, export formats and additional module options.

## Host-specific definitions

Since version 1.4.0, two optional host variables customize the generated definition.
Their names are selectable through the keyword-only parameters `fqdn_var` and
`overrides_var`. Their defaults are:

- `fqdn`: the DNS name to use instead of `<host>.<domain>`. It supplies the default
  `common_name` and the first DNS SAN. The `domain` argument can be omitted when
  every selected host has `fqdn`.
- `ca_certificate`: a dictionary of certificate options that override the
  generated defaults. Scalars, lists and dictionaries replace the corresponding
  value completely, except `san`: these SANs are appended to the automatic FQDN,
  inventory-name and IP SANs, with duplicates removed while retaining order.

To use different variable names:

```yaml
ca_certificates: >-
  {{ groups['webservers'] | jomrr.ca.host_certificates(
       hostvars, 'example.test', fqdn_var='inventory_fqdn',
       overrides_var='pki_certificate') }}
```

This reads `hostvars[host].inventory_fqdn` and
`hostvars[host].pki_certificate`. Selectors are exact variable names, not dotted
paths or expressions. The default names are then ignored. If a selected variable
is absent, the filter uses `<host>.<domain>` or the generated defaults respectively.
The domain can be omitted when every selected host supplies its selected FQDN
variable. Empty selector names and unknown keyword arguments raise errors.

With the default selectors, `host_vars/web02.yml` can contain:

```yaml
ansible_host: 2001:db8::20
fqdn: web02.other.test
ca_certificate:
  type: tls_client
  key_type: RSA
  key_size: 3072
  formats: [pem, bundle]
  san:
    - DNS:alias.other.test
```

The original call with `domain='example.test'` now produces this entry for `web02`;
`web01` keeps its existing defaults:

```yaml
- name: web02
  type: tls_client
  common_name: web02.other.test
  key_type: RSA
  key_size: 3072
  san: [DNS:web02.other.test, DNS:web02, 'IP:2001:db8::20', DNS:alias.other.test]
  formats: [pem, bundle]
```

Changing `type` does not reset the filter's `key_type` or `formats` defaults; use
the corresponding overrides when needed. An explicit `formats: []` removes the
optional exports. Additional options such as `days`, `subject`, `key_usage` or
`publish_private` are forwarded to the certificate modules. An override of
`common_name` does not alter the automatic DNS SANs: those still use the selected FQDN or
`<host>.<domain>`.

`name` may also be overridden. The result is sorted by the resulting name, and
duplicate resulting names raise an error. Duplicate input hosts still produce
only one definition; an empty host list returns an empty list. The filter leaves
its inputs untouched and copies nested override values, so result modifications
do not change host variables.

Only selected hosts and relevant variables are read. If present, the selected FQDN
must be a non-empty string and the selected overrides must be a dictionary. Invalid field
shapes and undefined values in selected fields raise errors. Unrelated host
variables need not be defined. `ansible_host` remains required for every host.

Use the result as `certificates` for `jomrr.ca.certificate_batch`, or loop over it
as `certificate` for `jomrr.ca.certificate`. Configure the issuing CA through
`certificate_types.<type>.issuer` and `authorities`, or set `issuer` in the
host-specific certificate overrides. Keep a type-map entry for each selected
type; its issuer is optional when the certificate specifies one.
