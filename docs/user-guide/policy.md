# Policy, bypass rules, protection, and grants

`gatefs` evaluates policy per filesystem effect. An effect has a policy layer (`READ`, `WRITE`, or `METADATA`) and a sandbox path.

For each effect:

1. a matching `bypass-*` rule automatically allows the effect without creating a pending request;
2. otherwise, a matching `protect-*` rule creates a pending authorization request;
3. otherwise, the effect is allowed by default.

The operation may execute only when all of its effects are allowed. If any effect is denied or canceled, the whole operation fails.

## Protection rules

Read/write protection rules are configured separately:

```sh
gatefs demo protect-read '/data/**'
gatefs demo protect-write '/data/**'
gatefs demo unprotect-read '/data/**'
gatefs demo unprotect-write '/data/**'
gatefs demo list-protection [--read] [--write]
```

Metadata protection is separate:

```sh
gatefs demo protect-metadata '/data/**'
gatefs demo protect-xattr '/data/**'
gatefs demo unprotect-metadata '/data/**'
gatefs demo unprotect-xattr '/data/**'
gatefs demo list-protection --metadata
gatefs demo list-protection --xattr
```

A matching protected effect becomes a pending authorization request. Inspect or resolve it with:

```sh
gatefs demo allow
gatefs demo allow <operation_id>
gatefs demo allow --do-nothing <operation_id>
gatefs demo deny <operation_id>
gatefs demo cancel <operation_id>
gatefs demo cancel-all [mountpoint]
gatefs-access-tui demo
```

Inspecting pending requests is read-only. Multiple CLI tools or Access TUI instances may view the same foreground session socket concurrently. `allow`, `allow --do-nothing`, `deny`, or lifecycle `cancel` resolves and removes a pending request. `cancel-all` cancels all pending requests in the sandbox, or only pending requests from the attached view identified by `<mountpoint>` when a mountpoint is provided.

`allow --do-nothing` releases the blocked FUSE request according to the normal do-nothing semantics for that request.

## Bypass rules

Bypass rules are automatic-allow exclusions from protection rules:

```sh
gatefs demo bypass-read '/data/**'
gatefs demo bypass-write '/data/**'
gatefs demo bypass-metadata '/data/**'
gatefs demo bypass-xattr '/data/**'
gatefs demo unbypass-read '/data/**'
gatefs demo unbypass-write '/data/**'
gatefs demo unbypass-metadata '/data/**'
gatefs demo unbypass-xattr '/data/**'
gatefs demo list-bypass [--read] [--write] [--metadata] [--xattr]
```

`bypass-*` rules are layer-specific. `bypass-write` automatically allows matching write effects, but it does not bypass metadata protection. `bypass-metadata` automatically allows matching metadata effects, but it does not bypass write protection.

`bypass-xattr` automatically allows matching xattr effects. For xattr reads, it can release operations that would otherwise be pending under `protect-read` or `protect-xattr`. For xattr mutations, it can release operations that would otherwise be pending under `protect-write`, `protect-metadata`, or `protect-xattr`. It does not bypass chmod, chown, chattr, timestamp, ordinary file-content, or namespace effects. `protect-xattr` and `bypass-xattr` apply to `getxattr`, `listxattr`, `setxattr`, and `removexattr`.

This matters because a single FUSE operation can have multiple effects. For example, truncate changes file size/content semantics, so it has a `WRITE` effect, but it also updates metadata. If `protect-metadata` matches and `bypass-metadata` does not, truncate must not automatically succeed even when its write effect is otherwise allowed or covered by `bypass-write`.

Hard link is another multi-effect operation: the source path has a `METADATA` effect because the source inode's link count and ctime change, while the destination path has a `WRITE` effect because a new directory entry is created.

## Common operation effects

This table describes the user-visible policy model for common FUSE operations. It is not a kernel trace of every incidental timestamp or ctime update; gatefs evaluates the explicit effects it exposes for protection and bypass decisions.

| Operation | Effect path(s) | Policy effect(s) |
| --- | --- | --- |
| Read regular file contents | File path | `READ` |
| List directory contents | Directory path | `READ` |
| Read symlink target | Symlink path | `READ` |
| Open for write, write, create file, create exclusive, `mknod`, `mkdir`, `symlink`, `unlink`, `rmdir` | Target path being opened, created, or removed | `WRITE` |
| Truncate or set file size | Target path | `WRITE` and `METADATA` |
| Rename | Source path and destination path | `WRITE` on each affected path |
| Hard link | Existing source path and new destination path | `METADATA` on the source path; `WRITE` on the destination path |
| `chmod`, `chown`, `chattr`, timestamp updates, inode-flag ioctls | Target path | `METADATA` |
| `setxattr`, `removexattr` | Target path | `WRITE`, `METADATA`, and `XATTR`; allowed xattr mutations are forwarded to the backing filesystem |
| `getxattr`, `listxattr` | Target path | `READ` and `XATTR`; allowed xattr reads are forwarded to the backing filesystem |
| `lookup`, `getattr`, opening a read handle, opening a directory handle | Target path | No protected effect by default |

Directory-entry operations use the entry path as the write effect path. For example, creating `/data/new` is a `WRITE` effect on `/data/new`, not a recursive write effect on `/data` or `/`. This keeps protection scoped to the path pattern the operator configured. If every create/delete also became a write on all ancestor directories, broad parent patterns would collapse most useful policy toward the root of the visible tree and make narrow protection rules much harder to reason about.

Operations that mutate directory entries still may change backing filesystem metadata such as directory timestamps or inode ctime. Those incidental backing updates do not turn the operation into a recursive ancestor `METADATA` policy effect. Explicit metadata operations remain separately gated by `protect-metadata`, and coupled operations listed above, such as truncate or hard link, model the explicit metadata effects that matter for policy decisions.

## Grants

For protected read/write requests, bare `allow <operation_id>` only releases the current blocked request.

Add grant options to create a future-matching read/write grant:

```sh
gatefs demo allow <operation_id> --path <sandbox-glob> --duration
gatefs demo allow <operation_id> --path <sandbox-glob> --duration=30m
gatefs demo allow <operation_id> --path <sandbox-glob> --tree
```

`--path <sandbox-glob>` chooses the grant path pattern. `--duration` or `--duration=<duration>` creates a duration grant; the default is 30 minutes. `--tree` snapshots the requester's current process tree instead of the exact requester process. If grant options are present without `--duration`, the grant is one-shot.

## Pattern semantics

A bypass or protection pattern is a sandbox namespace glob:

- `/a/b` matches that exact file or directory.
- `/a/b/` is directory-only.
- `/a/*` matches one path segment below `/a`.
- `/a/**` matches a recursive subtree below `/a`; it does not match `/a` itself.
- `/*/` matches one directory level below `/`, but not `/` itself.
- `/**/` matches non-root directories recursively, but not regular files and not `/` itself.

Patterns use Rust [`glob`](https://docs.rs/glob/) crate semantics with gatefs' directory-only handling for trailing `/`.

## Access TUI

The TUI displays pending requests and supports allow, deny, do-nothing, and edit-command. Edit-command reruns a user-edited `chmod`, `chown`, or `chattr` through the trusted `gatefs` CLI path, then releases the original pending request with do-nothing. Read/write TUI allow/deny/do-nothing resolves only the selected pending request and does not create broader grants.
