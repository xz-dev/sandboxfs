# Policy, protection, passthrough, and grants

`sandboxfs` has explicit policy layers for read, write, and metadata operations.

## Protection rules

Read/write protection rules are configured separately:

```sh
sandboxfs demo protect-read '/data/**'
sandboxfs demo protect-write '/data/**'
sandboxfs demo unprotect-read '/data/**'
sandboxfs demo unprotect-write '/data/**'
sandboxfs demo list-protection [--read] [--write]
```

Metadata protection is separate:

```sh
sandboxfs demo protect-metadata '/data/**'
sandboxfs demo unprotect-metadata '/data/**'
sandboxfs demo list-protection --metadata
```

A matching protected operation becomes a pending authorization request. Inspect or resolve it with:

```sh
sandboxfs demo allow
sandboxfs demo allow <operation_id>
sandboxfs demo allow --do-nothing <operation_id>
sandboxfs demo deny <operation_id>
sandboxfs demo cancel <operation_id>
sandboxfs demo cancel-all [mountpoint]
sandboxfs-access-tui demo
```

Inspecting pending requests is read-only. Multiple CLI tools or Access TUI instances may view the same foreground session socket concurrently. `allow`, `allow --do-nothing`, `deny`, or lifecycle `cancel` resolves and removes a pending request. `cancel-all` cancels all pending requests in the sandbox, or only pending requests from the attached view identified by `<mountpoint>` when a mountpoint is provided.

`allow --do-nothing` releases the blocked FUSE request without changing sandbox metadata or underlying files.

## Grants

For protected read/write requests, bare `allow <operation_id>` only releases the current blocked request.

Add grant options to create a future-matching read/write grant:

```sh
sandboxfs demo allow <operation_id> --path <sandbox-glob> --duration
sandboxfs demo allow <operation_id> --path <sandbox-glob> --duration=30m
sandboxfs demo allow <operation_id> --path <sandbox-glob> --tree
```

`--path <sandbox-glob>` chooses the grant path pattern. `--duration` or `--duration=<duration>` creates a duration grant; the default is 30 minutes. `--tree` snapshots the requester's current process tree instead of the exact requester process. If grant options are present without `--duration`, the grant is one-shot.

## Passthrough rules

Passthrough rules are layer-specific:

```sh
sandboxfs demo passthrough-read '/data/**'
sandboxfs demo passthrough-write '/data/**'
sandboxfs demo passthrough-metadata '/data/**'
sandboxfs demo unpassthrough-read '/data/**'
sandboxfs demo unpassthrough-write '/data/**'
sandboxfs demo unpassthrough-metadata '/data/**'
sandboxfs demo list-passthrough [--read] [--write] [--metadata]
```

`passthrough-read` and `passthrough-write` apply only to read/write operations. `passthrough-metadata` applies only to metadata operations. `passthrough-write` does not bypass metadata policy.

In this version, `passthrough-write` enables lock-directory `mkdir`/`rmdir` passthrough for matching visible paths. Other create/write/truncate/unlink/rename operations still return read-only or unsupported errors and never modify underlying files.

## Pattern semantics

A passthrough or protection pattern is a sandbox namespace glob:

- `/a/b` matches that exact file or directory.
- `/a/b/` is directory-only.
- `/a/*` matches one path segment below `/a`.
- `/a/**` matches a recursive subtree below `/a`; it does not match `/a` itself.
- `/*/` matches one directory level below `/`, but not `/` itself.
- `/**/` matches non-root directories recursively, but not regular files and not `/` itself.

Patterns use Rust [`glob`](https://docs.rs/glob/) crate semantics with sandboxfs' directory-only handling for trailing `/`.

## Access TUI

The TUI displays pending requests and supports allow, deny, do-nothing, and edit-command. Edit-command reruns a user-edited `chmod`, `chown`, or `chattr` through the trusted `sandboxfs` CLI path, then releases the original pending request with do-nothing. Read/write TUI allow/deny/do-nothing resolves only the selected pending request and does not create broader grants.
