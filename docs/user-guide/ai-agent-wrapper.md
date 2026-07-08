# AI agent wrapper notes

`example/pi-sandbox.sh` shows the intended integration shape for an AI coding agent:

1. use an existing sandboxing tool, such as Bubblewrap, for the process/container boundary;
2. use `sandboxfs` for the observable filesystem policy layer inside that boundary;
3. initialize the view and policy explicitly from a small script;
4. run the agent with only the paths and compatibility shims that workflow needs.

The wrapper is intentionally a demo and self-use example, not a general framework. It keeps the agent-facing filesystem view simple while using `sandboxfs` commands for the parts that need runtime visibility or adjustment.

## Why AI agents

AI agents are dynamic and tool-heavy. They often need to inspect source trees, invoke compilers, run tests, read tool configuration, write temporary files, and occasionally request access to paths that were not obvious before the task started.

Static filesystem policy is awkward for that workflow:

- broad bind mounts make the agent too powerful and reduce observability;
- narrow read-only mounts frequently break legitimate tools;
- changing policy usually requires restarting the sandboxed process;
- host path details can leak into prompts and authorization surfaces.

`sandboxfs` puts a dynamic policy shim in the middle. Sensitive filesystem operations can become pending requests, can be resolved without restarting the agent, and can be logged against the sandbox namespace.

## Script-first initialization

`sandboxfs` does not have a persistent configuration file. Agent wrappers should initialize policy through ordinary commands each time they start a session.

This keeps each integration explicit and avoids a configuration format that grows with every new compatibility need. For example, an AI agent wrapper can decide at startup which paths are visible, which PATH directories are write-protected, which lock directories need passthrough, and which operations should become pending authorization requests.

## Relationship to Bubblewrap and similar tools

Bubblewrap, containers, or VMs still provide the process boundary. `sandboxfs` does not replace that boundary.

Instead, `sandboxfs` replaces static filesystem permission layouts with runtime policy. In a typical wrapper, Bubblewrap decides what process environment exists, while `sandboxfs` decides which filesystem operations are visible, protected, granted, denied, logged, or passed through.
