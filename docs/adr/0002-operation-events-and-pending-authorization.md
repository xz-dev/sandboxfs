# ADR 0002: Operation events, audit logs, and nonblocking pending authorization

## Status

Accepted.

## Context

`sandboxfs` exposes a foreground, in-memory sandbox through FUSE. Metadata changes requested through an attached FUSE mount can come from untrusted tools, so they become pending authorization requests. The first implementation used shell-like descriptions such as `chmod 444 /data/file`, wrote log lines directly from several call sites, and blocked the FUSE handler thread while waiting for a user decision.

That design had three problems:

1. A filesystem can only observe FUSE/kernel operations, not the original shell command. Log and TUI vocabulary should therefore describe filesystem operations.
2. Direct log-file writes from multiple concurrent paths can race, reorder, or duplicate output. Logs are an audit stream and need one serialized writer.
3. A pending request must not freeze unrelated filesystem access. A tool asking for one metadata change should not make other paths unusable while the user decides.

## Decision

### Operation vocabulary

The canonical event body uses filesystem/FUSE-style operation descriptions. Examples:

```text
path=/data/file.txt SETATTR mode=0600
path=/data/file.txt SETATTR uid=1000
path=/data/file.txt SETATTR gid=1000
path=/data/file.txt CHATTR flags=0x10
```

The Access TUI displays the selected pending request with the operation ID first, then target path, then operation details. Path-edit/path-modification is explicitly out of scope; the TUI may still support allow, deny, do-nothing, and edit-command through trusted metadata commands.

### Audit log grammar

Every log entry has its own event ID and a bracketed UTC timestamp with microsecond precision:

```text
[2026-06-29T13:55:12.123456Z] id=3 pending path=/data/file.txt SETATTR mode=0600
[2026-06-29T13:55:13.000042Z] id=4 decision request=3 ALLOW
[2026-06-29T13:55:14.999999Z] id=5 trusted trusted=2 path=/data/file.txt SETATTR mode=0444
```

Authorization decisions are separate events with fresh event IDs. The `request=<pending-id>` field links a decision back to the pending request. Decision kinds include `ALLOW`, `ALLOW_DO_NOTHING`, and `DENY`; automatic replacement uses normal deny semantics with a reason such as `reason=superseded`.

Default logs are audit/review oriented. High-frequency operations such as `LOOKUP`, `GETATTR`, `READ`, and `READDIR` may have formatters for debugging, but they are not written by default.

### Serialized log writer

Runtime code publishes log events to a single log-writer loop. The writer loop is the only code that opens log files for reset, append, or removal. FUSE handlers, IPC handlers, and trusted-command paths must not append directly to log files.

### Pending authorization and replacement

A pending metadata request does not change current metadata. Until the request is allowed, reads, opens, stats, and other operations continue under the currently effective metadata.

Pending replacement is keyed by:

```text
sandbox + target path + operation kind
```

Operation kinds are intentionally fine-grained:

- `mode`
- `uid`
- `gid`
- `flags`

A later request with the same key behaves as if the user denied the earlier request first, then the later request arrived. The earlier blocked FUSE operation is unblocked with deny semantics. Requests with different keys can remain pending independently; for example, same-path `uid` and `gid` requests do not cancel each other.

### Ext4-like metadata effects on open files

`sandboxfs` should mimic ext4 metadata behavior as closely as practical:

- `chmod`/`chown` changes do not revoke already-open file descriptors.
- New opens observe allowed/applied metadata overrides.
- Once `chattr +i` is allowed/applied, later writes should fail even through already-open writable descriptors. Current content writes remain read-only unless a later design adds sandbox-local content writes.

### Nonblocking FUSE request handling

Pending authorization must not block unrelated path access. The implementation may use fuser reply objects from a worker thread instead of migrating to fuser's experimental async API. The FUSE handler should register a pending operation and return quickly; a waiter/worker completes the FUSE reply after authorization.

## Consequences

- Logs are stable audit records rather than command-line reconstructions.
- Log ordering and write integrity are centralized in one writer loop.
- The pending queue needs indexes by operation key in addition to request ID.
- Multi-field `SETATTR` requests may split into several fine-grained pending requests. The original FUSE request must still complete consistently if any member is denied or superseded.
- Tests must include deterministic concurrency/stress coverage for logging, replacement, decision ordering, and cleanup, plus gated real-FUSE coverage where kernel behavior matters.
