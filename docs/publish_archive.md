# jomrr.ca.publish_archive

`jomrr.ca.publish_archive` creates a deterministic tar archive on the CA host
from authority definitions or explicit public AIA/CDP artifacts. Transfer the
archive and unpack it on the publication host in separate playbook tasks.

## Parameters

- **`base_dir`**: CA base directory used for the module lock.
  Required: yes Default:; Allowed values: existing CA base directory

- **`dest`**: Archive path on the managed host.
  Required: yes Default:; Allowed values: path

- **`authorities`**: Managed authorities used to derive default AIA/CDP
  artifacts.
  Required: no; Default: `[]`; Allowed values: list of authority dictionaries

- **`artifacts`**: Explicit public artifacts to include. Each item needs `src`,
  `file`, and `area`; when set, this overrides authority-derived artifacts.
  Required: no; Default: `[]`; Allowed values: list of artifact dictionaries

- **`artifact_mode`**: Mode stored for files inside the archive.
  Required: no; Default: `0644`; Allowed values: octal mode string

- **`owner`**: Owner for the generated archive file.
  Required: no Default:; Allowed values: user name

- **`group`**: Group for the generated archive file.
  Required: no Default:; Allowed values: group name

- **`mode`**: Filesystem mode for the generated archive file.
  Required: no; Default: `0600`; Allowed values: octal mode string

- **`force`**: Rewrite the archive even when content is identical.
  Required: no; Default: `false`; Allowed values: `true`, `false`

Artifact `area` values:

- `aia` writes the file below `aia/` in the archive.
- `cdp` and `crl` write the file below `crl/` in the archive.

Only plain filenames are accepted for artifact `file`; path separators are
rejected. This keeps archive extraction paths fixed below `aia/` and `crl/`.

When `authorities` is used, the module derives the role defaults:

- AIA gets every retained CA generation as `pem`, `der`, and `txt`.
- The first generation keeps `<name>-ca.*`; subsequent generations use
  `<name>-ca-<generation_id>.*`. The original URL is never reassigned to a new key.
- CDP includes matching CRLs for every generation at the same generation-specific
  stems. Run `crl` first; missing active exports cause publication to fail.
- Retired generations keep their public CA certificates and any existing final
  CRL. Publication does not require a retired signing key or create another CRL.
- AIA gets every issuing CA chain as `pem`, `der`, and `txt`.
- CDP gets every CRL as `pem` and `der`.
- Self-signed root CAs do not get chain files because they would be identical
  to the root certificate.

Authority-derived publication requires `cryptography >= 43` on the managed host.
Explicit `artifacts` remain literal and override this generation discovery. When
using that override, include every needed generation yourself and preserve the
URLs embedded in existing certificates. The current file `ca/<name>-ca.der` must
not replace a legacy AIA URL belonging to an older key. Prefer `authorities` for
automatic rollover handling. See [CA rollover](authority.md#ca-key-rollover-and-publication).

## Behavior

- The archive is deterministic: file mtimes are `0`, uid/gid are `0`, owner and
  group names are empty, and files are sorted.
- Publish tasks let
  `ansible.builtin.unarchive` compare the actual target files with the archive
  and restore missing or changed files.
- The module compares the generated archive with the existing `dest` content
  and only rewrites on content or metadata changes, unless `force=true`.
- Writes are protected by the role's publish archive lock below
  `<base_dir>/.locks`.
- The module only reads public CA, chain, and CRL artifacts; it should not be
  used for private keys or private bundles.

## Example

```yaml
- name: Build CA publish archive
  jomrr.ca.publish_archive:
    base_dir: /etc/pki/example
    dest: /tmp/example-public.tar
    authorities: "{{ ca_authorities }}"
    artifact_mode: "0644"
    owner: root
    group: root
    mode: "0600"
```

## Return Values

- **`changed`**: Whether the archive file was written or its metadata changed.
  Type: `bool`

- **`path`**: Archive path on the managed host.
  Type: `str`

- **`archive_paths`**: Relative paths stored in the archive.
  Type: `list`
