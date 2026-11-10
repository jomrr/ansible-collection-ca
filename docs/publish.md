# jomrr.ca.publish

`jomrr.ca.publish` writes public AIA/CDP files directly into a webroot on the CA
host in one module invocation. It uses the same artifact selection as
[`jomrr.ca.publish_archive`](publish_archive.md), including retained issuer
generations and their active or final CRLs. Run `jomrr.ca.crl` first.

## Parameters

- `base_dir`: Required CA base directory, including its publication locks.
- `dest`: Required destination webroot on the same managed host.
- `authorities`: Authority definitions used to discover public artifacts;
  defaults to `[]`. This path requires `cryptography >= 43`.
- `artifacts`: Explicit public files overriding `authorities`; defaults to `[]`.
  Each entry has `src`, `file` and `area`. Areas `aia`, `cdp` and `crl` map to
  fixed `aia/` and `crl/` directories; `file` must be a plain filename.
- `owner`, `group`: Optional owner and group for published files.
- `mode`: Published file mode, default `0644`.
- `force`: Rewrite even identical files, default `false`.

Provide nonempty `authorities` or `artifacts`. Explicit artifacts must preserve
all issuer generations needed by existing certificates and their original URLs.

## Example

```yaml
- name: Publish on the CA host
  become: true
  become_user: root
  jomrr.ca.publish:
    base_dir: /etc/pki/example
    dest: /var/www/pki
    authorities: "{{ ca_authorities }}"
    owner: root
    group: root
    mode: "0644"
```

The execution user must be able to access CA data and locks and write the
destination. Configure privilege escalation as needed. Manage directory ownership
and permissions separately; the standalone role creates these directories before
publication.

## Behavior and Returns

Files are compared byte for byte and written atomically only when changed or
forced. Ownership and mode drift is corrected; missing files are restored.
Unrelated destination files remain untouched. Unsafe filenames and duplicate
publication paths fail. Writes reject symlinks at destination path components.
No archive, fetch or controller staging is used.

Returns `path` (the destination webroot), `published_paths` (sorted relative
paths) and `changed` (content or attribute changes). Check mode skips the module
without mutation; diff output is not supported.
