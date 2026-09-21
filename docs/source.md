# Source provenance

Ported from `jomrr/ansible-role-ca`, commit
`0e59800e7528dbe2ad8eeaaf962a849f25d0bd92` (Jonas Mauer).
The collection and its ported sources are licensed under GPL-3.0-or-later.
The source role remains unchanged. The retained reference pages describe the
original file layout and models; collection module documentation is authoritative.

Public modules drop the role-local `ca_` prefix. Utilities are internal to this
collection and use collection-qualified imports. The controller filter is
`jomrr.ca.authority_map`. FRITZ!Box TLS verification remains disabled by default for self-signed device certificates.
