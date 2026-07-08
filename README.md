# sandboxfs

`sandboxfs` is an experimental, observable filesystem protection shim built on [`fuser`](https://github.com/cberner/fuser). It gives a process a FUSE-backed filesystem view whose read, write, and metadata permissions can be inspected, protected, granted, denied, and adjusted at runtime.

It is designed to complement existing sandboxing tools such as Bubblewrap, containers, or VM-based runners, not to replace them. Those tools still provide the process boundary; `sandboxfs` adds the dynamic filesystem policy layer that static bind mounts and read-only mounts do not provide.

The initial design target is AI agents: they are unusually dynamic, tool-heavy, and hard to predict ahead of time, so static filesystem permissions are often either too broad to be useful or too narrow to let the agent finish the task. `sandboxfs` focuses on observability and controllability for that workflow.

`sandboxfs` is script-initialized by design. It intentionally avoids a persistent configuration file format so integrations can compose ordinary commands for each workflow instead of growing a complex project-specific config schema over time.

## Install from source

Prerequisites:

- Rust 1.88 or newer.
- Linux FUSE support, including `/dev/fuse` and `fusermount3`, for real mount tests and normal FUSE use.

Build locally:

```sh
git clone https://github.com/xz-dev/sandboxfs.git
cd sandboxfs
cargo build --release
```

Install the binaries into Cargo's bin directory:

```sh
cargo install --path .
```

This installs:

- `sandboxfs`
- `sandboxfs-access-tui`

## Quick start

Start a foreground session in one terminal:

```sh
sandboxfs run demo
```

In another terminal, map local data into the sandbox namespace and expose it through FUSE:

```sh
DEMO_MNT="$(mktemp -d)"
sandboxfs demo mount /some/local/dir /
sandboxfs demo attach "$DEMO_MNT"
ls "$DEMO_MNT"
cat "$DEMO_MNT/file.txt"
```

Add a protection rule when an operation should become observable and adjustable at runtime:

```sh
sandboxfs demo protect-read '/**'
cat "$DEMO_MNT/file.txt" # blocks and creates a pending request
sandboxfs demo allow
sandboxfs demo allow <operation_id>
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

## AI agent wrapper example

`example/pi-sandbox.sh` shows the intended integration shape for an AI coding agent: use Bubblewrap for the process/container boundary, then put `sandboxfs` inside that boundary as the observable filesystem policy layer. The wrapper keeps the agent-facing view simple while allowing selected paths, PATH tools, lock directories, and protected operations to be managed through `sandboxfs` policy instead of static bind mounts alone.

## Documentation

- [Documentation index](docs/README.md)
- [Concepts and lifecycle](docs/user-guide/concepts.md)
- [Command reference](docs/user-guide/commands.md)
- [Policy, protection, passthrough, and grants](docs/user-guide/policy.md)
- [Metadata operations](docs/user-guide/metadata.md)
- [Logs, runtime paths, and limitations](docs/user-guide/runtime-and-limits.md)
- [AI agent wrapper notes](docs/user-guide/ai-agent-wrapper.md)
- [Development checks](docs/user-guide/development.md)
- [Architecture decisions](docs/adr/)

## Current status

`sandboxfs` is experimental. It is not a complete process sandbox or security boundary by itself; use it with an existing sandboxing or runtime isolation tool when process isolation is required.

In this version, file content and directory structure writes are read-only unless a path matches an explicit passthrough rule for a supported operation. `passthrough-write` currently enables lock-directory `mkdir`/`rmdir` passthrough, and `passthrough-metadata` enables timestamp and xattr metadata passthrough for matching visible paths. Other create/write/truncate/unlink/rename operations still return read-only or unsupported errors and never modify underlying files.
