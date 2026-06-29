# Context Glossary

## Sandbox
A named, in-memory filesystem namespace. A sandbox disappears when its owning live session ends or it is destroyed.

## Sandbox Session
The live lifecycle of one sandbox. A session begins when the user runs `sandboxfs run <name>` and ends when that foreground process exits or receives a destroy/shutdown control command.

## Control Command
A short-lived user command that asks an existing foreground sandbox session to change or inspect the sandbox through that session's runtime socket.

## Attach
Exposing a sandbox at a host mountpoint so normal filesystem tools can access it.

## Mapping
A rule that makes an existing local file or directory visible at a sandbox path.

## Hide Rule
A rule that removes a sandbox path and its descendants from visibility until a newer mapping covers that path again.

## Metadata Override
A sandbox-local metadata change, such as mode, owner, group, or flags, that does not change the underlying local file or directory.

## Pending Metadata Request
An untrusted metadata change requested through an attached filesystem that must be allowed or denied by the user.

## Trusted Metadata Operation
A metadata operation initiated through sandboxfs itself, which skips the pending authorization flow but can still fail normally.

## Operation Event
A structured filesystem operation notification used before string formatting. Operation events carry an event ID, timestamp, sandbox, target path, operation kind, and operation fields. Logs and TUI text are renderings of operation events, not reconstructions of shell commands.

## Audit Log Entry
A serialized operation or lifecycle record written by the session log writer. Every audit log entry has a bracketed UTC timestamp with microsecond precision and its own `id=<event-id>`.

## Log Writer
The single writer loop responsible for resetting, appending to, and removing sandbox log files. Filesystem handlers and control handlers publish log events to the writer instead of writing log files directly.

## Decision Event
A log event recording a user or system authorization decision. It has its own event ID and references the pending request with `request=<pending-id>`. Decision kinds are `ALLOW`, `ALLOW_DO_NOTHING`, and `DENY`.

## Pending Operation Kind
The replacement dimension for pending metadata authorization on a target path. Current kinds are `mode`, `uid`, `gid`, and `flags`. A later request with the same sandbox, path, and kind denies and replaces the earlier pending request; different kinds can remain pending independently.

## Superseded Pending Request
A pending request that was automatically denied because a later request with the same sandbox, target path, and operation kind arrived. This is behaviorally the same as the user denying the earlier request before the later request becomes pending.

## Ext4-like Open File Semantics
Metadata changes should match ext4 behavior as closely as practical: chmod/chown do not revoke already-open file descriptors, new opens observe allowed metadata overrides, and immutable flags should reject later writes once applied.
