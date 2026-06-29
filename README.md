# sandboxfs

`sandboxfs` is an experimental, in-memory overlay sandbox filesystem built on [`fuser`](https://github.com/cberner/fuser).

The important lifecycle rule is explicit foreground ownership: a sandbox exists only while a visible `sandboxfs run <name>` process is running. There is no hidden `sandboxfsd`, no automatic daemon startup, and no global `list` command.

## Basic usage

Start a foreground sandbox session in one terminal:

```sh
sandboxfs run demo
```

In another terminal, map local data into the sandbox and expose it through FUSE:

```sh
DEMO_MNT="$(mktemp -d)"
sandboxfs demo mount /some/local/dir /
sandboxfs demo attach "$DEMO_MNT"
ls "$DEMO_MNT"
cat "$DEMO_MNT/file.txt"
```

Unmount one attach point:

```sh
sandboxfs demo detach "$DEMO_MNT"
rmdir "$DEMO_MNT"
```

Stop the foreground session and drop all in-memory state:

```sh
sandboxfs demo destroy
```

Ctrl-C in the `sandboxfs run demo` terminal also stops the session.

## Commands

```text
sandboxfs run <name>
sandboxfs <name> destroy
sandboxfs <name> attach <mountpoint>
sandboxfs <name> detach <mountpoint>
sandboxfs <name> mount <local> <on_fs>
sandboxfs <name> mount
sandboxfs <name> umount <on_fs>
sandboxfs <name> hide <on_fs>
sandboxfs <name> chmod ...
sandboxfs <name> chown ...
sandboxfs <name> chattr ...
sandboxfs <name> allow [operation_id]
sandboxfs <name> allow --do-nothing <operation_id>
sandboxfs <name> deny <operation_id>
sandboxfs <name> monitor [-f]
sandboxfs <name> metadata
sandboxfs-access-tui <name>
```

`mount` without arguments lists mappings and hide rules for the sandbox. `allow` without arguments lists pending metadata requests.

## Overlay and hide behavior

Mappings are added with:

```sh
sandboxfs demo mount <local_path> <sandbox_path>
```

Later mappings overlay earlier mappings, similar to mounts. Intermediate sandbox directories that do not exist in the underlying local filesystems are virtual, in-memory directories.

Hide a sandbox subtree with:

```sh
sandboxfs demo hide /path/in/sandbox
```

A hide rule removes that path and descendants from visibility until a newer mapping covers that path again.

## Metadata operations

`sandboxfs demo chmod/chown/chattr ...` creates a temporary FUSE mountpoint under the runtime directory, runs the command name found through `PATH`, and then immediately detaches and removes the temporary mountpoint.

These trusted CLI-initiated operations skip the pending authorization flow, but they can still fail normally if the command fails, the path does not exist, or the FUSE operation is unsupported. They only update sandbox-local metadata overrides; they do not chmod/chown/chattr the underlying files.

Direct metadata changes through an attached FUSE mountpoint are untrusted. For example:

```sh
chmod 444 "$DEMO_MNT/file.txt"
```

That request becomes pending. Inspect or resolve it with:

```sh
sandboxfs demo allow
sandboxfs demo allow <operation_id>
sandboxfs demo allow --do-nothing <operation_id>
sandboxfs demo deny <operation_id>
sandboxfs-access-tui demo
```

`allow --do-nothing` lets the blocked FUSE request return success without changing sandbox metadata or underlying files.

The TUI displays pending requests and supports allow, deny, do-nothing, and edit-command. Edit-command reruns a user-edited `chmod`, `chown`, or `chattr` through the trusted `sandboxfs` CLI path, then releases the original pending request with do-nothing.

## Logs and monitoring

Show the operation log:

```sh
sandboxfs demo monitor
sandboxfs demo monitor -f
```

`monitor` prints the recent log tail; `monitor -f` starts at the same tail and follows new log entries. Logs are reset when `sandboxfs run <name>` starts and are removed when the sandbox is destroyed.

Audit log entries use filesystem-operation vocabulary rather than shell command reconstruction. Every entry has a UTC microsecond timestamp and its own event ID, for example:

```text
[2026-06-29T13:55:12.123456Z] id=3 pending path=/data/file.txt SETATTR mode=0600
[2026-06-29T13:55:13.000042Z] id=4 decision request=3 ALLOW
[2026-06-29T13:55:14.999999Z] id=5 trusted path=/data/file.txt SETATTR mode=0444
```

The log writer is a serialized event loop. FUSE and control paths publish events to it instead of appending directly from concurrent call sites.

## Runtime paths

- `SANDBOXFS_RUNTIME_DIR` overrides the runtime directory.
- Without an override, `sandboxfs` asks `directories-rs` (`directories::ProjectDirs`) for the project runtime directory.
- If the platform has no project runtime directory, it falls back to the project cache directory with a `run` child.
- Runtime directories are created with mode `0700`.
- Socket path defaults to `<runtime>/<name>.sock`.
- `SANDBOXFS_SOCKET` overrides the socket path for special cases and tests.
- Log path defaults to `<runtime>/<name>.log`.
- `SANDBOXFS_LOG_DIR` overrides the log directory.
- Temporary trusted-operation mountpoints live under `<runtime>/tmp/`.

## Current limitations

- File content and directory structure writes are intentionally read-only in this first version: create/write/truncate/unlink/rename/mkdir/rmdir return read-only or unsupported errors and never modify underlying files.
- Real FUSE behavior depends on `/dev/fuse` and `fusermount3` availability and permissions.
- The project is experimental.

## Development checks

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
SANDBOXFS_RUN_FUSE_TESTS=1 cargo test --test fuse_behavior -- --ignored
```
