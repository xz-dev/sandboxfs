# ADR 0005: Keep policy path-scoped while binding metadata overrides to resolved layers

## Status

Accepted.

## Context

sandboxfs is a layered namespace filesystem. Mounts and hides are ordered overlay entries: a later mount can cover an earlier mount or hide, a later hide can cover earlier mounts, multiple mounts on the same sandbox path stack, and `umount` removes the newest matching mount so the previous layer is revealed. Later mounts below a hidden parent create read-only virtual ancestor directories so explicitly re-added paths remain reachable without leaking lower hidden directory contents.

Read/write authorization, grants, trusted metadata scopes, and sandbox-local metadata overrides all operate in that layered namespace. If these features are not assigned clear identities, later remounts and hides can make state ambiguous. For example, a metadata override recorded only as `/x/file` can accidentally apply to a different backing layer after another mount shadows `/x`, while a read/write grant recorded only by path may or may not be intended to follow future remounts.

## Decision

sandboxfs separates three concepts:

1. **Namespace overlay stack.** Mounts and hides are the filesystem shape. Resolution evaluates the ordered overlay stack and returns one of: real backing object, derived read-only virtual directory, hidden, or missing. This stack is the only source of path visibility.

2. **Path-scoped policy overlays.** Read/write protection rules, read/write grants, and trusted metadata scopes are policy over the final sandbox namespace path. They are not tied to host paths, backing inode identity, or a specific mount layer. A rule or grant for `/root/**` continues to apply to later visible mounts under `/root` unless the policy is explicitly removed, denied, expired, or otherwise invalidated by its own policy lifetime. This preserves operator intent: policies name the sandbox-visible path scope, not the underlying host object that happened to back that path when the policy was created.

3. **Resolved-layer metadata overlays.** Sandbox-local metadata overrides are tied to the resolved backing layer object at the time the metadata operation is authorized/applied. The override identity must include enough information to distinguish stacked mounts at the same sandbox path, such as the resolved mount layer id plus the relative path within that layer. Virtual directories may still have virtual metadata derived by sandboxfs, but file/directory metadata overrides for real backing objects must not be keyed only by sandbox namespace path.

This means metadata override behavior follows the namespace stack:

- If layer A is mounted at `/x` and `/x/file` receives a sandbox-local chmod override, the override belongs to layer A's `/file` object.
- If layer B is later mounted at `/x`, layer B shadows layer A and does not inherit layer A's metadata override.
- If layer B is unmounted, layer A is revealed again and layer A's override becomes visible again.
- If the same sandbox path resolves to a different layer, metadata pending decisions must apply to the object that was resolved for that pending request, not whatever object happens to occupy the path when the user later allows it.

## Consequences

The current namespace overlay evaluator remains the authority for visibility and real-vs-virtual resolution.

Read/write authorization and grants should continue to use sandbox namespace paths and path patterns. Tests should cover that path-scoped protection applies to later re-added visible descendants through hidden ancestors and through later remounts when the path pattern matches.

Metadata override storage and pending metadata requests need to carry resolved-layer identity. A path-only metadata map is insufficient for Linux-like mount-stack behavior because it can leak overrides across remounts. The implementation should migrate from `BTreeMap<SandboxPath, MetadataOverride>` toward a key that represents the resolved object, for example `{ layer_id, relative_path }` for real backing objects, with explicit handling for virtual directories if sandbox-local virtual metadata is ever needed.

Metadata pending replacement should also use the resolved object identity plus operation kind, not only sandbox path plus operation kind. Two pending chmod operations against the same visible path should replace each other only when they target the same resolved object. If the path is remounted between the two operations, the old pending request belongs to the old layer and the new pending request belongs to the new layer.

User-visible logs, TUI text, and CLI output should continue to display sandbox namespace paths rather than host paths or internal layer keys. Layer/object identity is internal state used to preserve correct stack semantics; it is not an authorization subject and must not expose host paths.
