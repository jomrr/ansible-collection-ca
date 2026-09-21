# plugins/filter/authority_map.py

Internal Ansible filter plugin for CA role variable normalization.

`plugins/filter/authority_map.py` exposes authority validation. Role tasks use it to
validate and address `ca_authorities` by name.

## Exported Filters

- **`jomrr.ca.authority_map`**
  Purpose: Returns authorities keyed by `name` after validating list shape, safe
  names, uniqueness, and parent references.

## Behavior

- `None` is treated as an empty list.
- Non-list inputs fail.
- Each item must be a dictionary.
- Each authority requires `name`.
- Each authority requires `parent`.
- Names must match `^[A-Za-z0-9_.-]+$`.
- Duplicate names fail.
- Every `parent` must reference an authority in the same list.

## Defaults

The filter has no default authorities. Defaults are supplied by role variables,
not by the filter.

## Example

```yaml
- name: Build authority lookup
  ansible.builtin.set_fact:
    ca_authorities_by_name: "{{ ca_authorities | jomrr.ca.authority_map }}"
```

## Used By

- Role tasks that need deterministic authority lookup before invoking modules.
- `tasks/publish.yml`
