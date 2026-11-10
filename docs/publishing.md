# AIA/CDP Publishing

The collection offers two modules with shared generation-aware artifact selection:

- [`jomrr.ca.publish`](publish.md) writes public files directly into a webroot
  on the CA host.
- [`jomrr.ca.publish_archive`](publish_archive.md) creates a deterministic
  archive for transfer and extraction on other hosts.

Both publish CA certificates and issuing chains under `aia/`, and CRLs under
`crl/`. Retained issuer generations keep their original URLs. Generate CRLs with
`jomrr.ca.crl` before publishing. Private keys are not part of authority-derived
publication.

The standalone role selects direct publication when a target's inventory name
equals `inventory_hostname`. It uses the target's `become` and `become_user`
settings. Other targets receive archives through the controller, shared by
remote file mode. The collection itself does not orchestrate remote transfers.

Direct publication manages destination directories with `directory_mode`, `owner`
and `group`. For archive extraction, manage these directories on the destination
host. Configure an HTTP
server separately to serve the `aia` and `crl` paths at the URLs embedded in the
certificates.
