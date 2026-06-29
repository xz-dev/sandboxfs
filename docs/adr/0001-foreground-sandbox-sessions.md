# Use foreground sandbox sessions instead of a background daemon

Sandbox state is owned by an explicit `sandboxfs run <name>` foreground process, not by an auto-started `sandboxfsd`. Control commands connect to that foreground session over its per-sandbox runtime socket, which keeps the in-memory lifecycle visible to the user and avoids hidden background state while still allowing other terminals and the TUI to control the running sandbox.
