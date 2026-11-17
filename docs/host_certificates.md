# jomrr.ca.host_certificates

Build TLS server certificate definitions from a list of short inventory host
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
hosts | jomrr.ca.host_certificates(hostvars, domain,
                                 key_type='P-384',
                                 formats=['pem', 'der', 'txt', 'fullchain'])
```

`domain` is appended with a dot to each input host name. `key_type` and `formats`
are copied into each definition; the certificate modules validate supported key
types and formats. The filter preserves its inputs and gives each result its own
formats list. Duplicate hosts produce one definition; an empty host list returns
an empty list.

Use the result as `certificates` for `jomrr.ca.certificate_batch`, or loop over it
as `certificate` for `jomrr.ca.certificate`. Configure the issuing CA through
`certificate_types.tls_server.issuer` and `authorities` as usual.
