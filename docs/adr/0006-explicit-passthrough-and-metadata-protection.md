# ADR 0006: Split passthrough and protection by policy layer

## Status

Accepted, partially superseded by [ADR 0007](0007-bypass-and-effect-based-authorization.md).

ADR 0007 supersedes this ADR's `passthrough-*` naming and the intentionally narrow `passthrough-write` behavior. ADR 0004 and ADR 0007 also supersede this ADR's historical xattr/default-metadata forwarding assumptions: current xattr mutations are forwarded to the backing filesystem when metadata policy allows them, not only when matched by the historical `passthrough-metadata` rule. The layer split and glob pattern semantics remain applicable.

## Context

sandboxfs has separate policy layers:

1. The namespace overlay stack (`mount`, `hide`, `umount`) decides which sandbox paths are visible and what backing object, if any, they resolve to.
2. Read/write operation policy controls file-content and directory-structure operations such as reading files, reading directories, opening for write, creating files, creating directories, removing directories, and renaming paths.
3. Metadata policy controls metadata operations such as chmod, chown, chattr, timestamp updates, and xattr updates.
4. Sandbox-local metadata overlays can present changed metadata without mutating the backing filesystem.

The existing implementation protected direct metadata mutations by default: a direct chmod/chown/chattr/timestamp/xattr operation through a FUSE attach became a pending request unless it came from a trusted sandboxfs CLI metadata helper. That default conflated "metadata is a managed surface" with "metadata is protected by default." It also made it hard to express a narrow operational need such as allowing Pi's lock-directory timestamps while keeping broader home-directory state hidden.

The `example/pi-sandbox.sh` wrapper exposes a concrete case. Pi's settings and trust loaders use `proper-lockfile`, which creates lock directories such as `$HOME/.pi/agent/settings.json.lock` and `$HOME/.pi/agent/trust.json.lock`, updates their timestamps, stats them, and removes them. With `$HOME` hidden and only selected descendants re-exposed through sandboxfs, directory creation/removal belongs to the read/write operation layer while timestamp updates belong to the metadata layer. One command that bypasses both layers would blur policy boundaries.

Path patterns for these policies are also becoming more expressive. `protect-*`, `unprotect-*`, and the new `passthrough-*` commands all need consistent glob semantics, including preserving a trailing slash as a directory-only pattern. The previous hand-written matcher only supported a small subset and normalized paths through `SandboxPath`, which loses trailing slash intent.

## Decision

sandboxfs keeps passthrough and protection rules strictly split by policy layer.

### Read/write operation policy

The read/write layer uses these commands:

```text
sandboxfs <name> protect-read <glob>
sandboxfs <name> protect-write <glob>
sandboxfs <name> unprotect-read <glob>
sandboxfs <name> unprotect-write <glob>
sandboxfs <name> passthrough-read <glob>
sandboxfs <name> passthrough-write <glob>
sandboxfs <name> unpassthrough-read <glob>
sandboxfs <name> unpassthrough-write <glob>
sandboxfs <name> list-protection [--read] [--write] [--metadata]
sandboxfs <name> list-passthrough [--read] [--write] [--metadata]
```

`passthrough-read` and `passthrough-write` apply only to read/write filesystem operation intent. They must not bypass metadata management. In the initial implementation, `passthrough-write` is intentionally narrow and covers only lock-directory creation and removal through `mkdir` and `rmdir` on matching visible directories. Other write-class operations such as create, mknod, symlink, link, unlink, rename, open-for-write, write, and truncate remain read-only or unsupported until a later explicit slice implements them. `passthrough-write` does not cover chmod/chown/chattr/timestamp/xattr behavior.

### Metadata policy

The metadata layer uses explicit commands:

```text
sandboxfs <name> protect-metadata <glob>
sandboxfs <name> unprotect-metadata <glob>
sandboxfs <name> passthrough-metadata <glob>
sandboxfs <name> unpassthrough-metadata <glob>
```

Metadata is no longer protected by default. Direct metadata operations that do not match `protect-metadata` and do not match `passthrough-metadata` use the existing sandbox-local metadata behavior where applicable, without creating a pending request. Only `protect-metadata` creates pending metadata authorization. Only `passthrough-metadata` forwards metadata mutation to the backing filesystem.

This supersedes the implicit metadata-protected behavior and the earlier xattr-specific write-gating assumption. Xattr mutations are metadata operations and therefore follow the same explicit metadata policy model: default behavior is not a pending request, `protect-metadata` gates them, and `passthrough-metadata` forwards them to the backing filesystem.

### Glob semantics

All policy commands above use a shared glob-pattern matcher implemented with the Rust `glob` crate rather than the previous hand-written matcher. Patterns are sandbox namespace patterns, not host paths.

Pattern conventions:

- `/a/b` is an exact path and may refer to either a file or a directory.
- `/a/b/` is an exact directory-only path. The trailing slash is semantic and must not be discarded.
- `/a/*` matches entries one level below `/a`.
- `/a/**` matches the recursive subtree below `/a`.
- `/a/*/` matches child directories one level below `/a`.
- More complex forms such as `/a/*/**` are interpreted by the shared glob matcher and retain directory-only meaning when the pattern ends in `/`.

Policy matching never grants visibility by itself. A passthrough or protection rule can only affect a path that is visible through the namespace overlay stack. Hidden paths remain hidden.

### Pi sandbox lock directories

`example/pi-sandbox.sh` should keep `$HOME` hidden and re-expose only the needed user config/workspace paths. For Pi's lock directories it should use separate rules:

```sh
sf passthrough-write "$HOST_HOME/.pi/agent/settings.json.lock"
sf passthrough-metadata "$HOST_HOME/.pi/agent/settings.json.lock"
sf passthrough-write "$HOST_HOME/.pi/agent/trust.json.lock"
sf passthrough-metadata "$HOST_HOME/.pi/agent/trust.json.lock"
```

The write rules cover lock-directory creation/removal. The metadata rules cover timestamp updates. The wrapper must not bind the entire `.pi` or `.agents` trees over the sandboxfs view as a shortcut, because that would bypass sandboxfs visibility and logging for too broad a scope.

## Consequences

The command/API model becomes larger, but each command has a single policy-layer meaning.

The policy matcher must preserve raw glob strings and trailing slash intent instead of storing policy patterns as normalized `SandboxPath` values.

Existing tests that assumed metadata operations always create pending requests need to be updated: pending should now occur only under explicit `protect-metadata`. Separate tests should cover default sandbox-local metadata behavior, protected metadata behavior, metadata passthrough behavior, and the Pi lock-directory combination of write and metadata passthrough.

README and user-facing help should describe that read/write passthrough and metadata passthrough are separate. In particular, `passthrough-write` intentionally does not imply `passthrough-metadata`.
