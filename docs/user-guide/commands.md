# Command reference

```text
sandboxfs run <name>
sandboxfs <name> destroy
sandboxfs <name> attach <mountpoint>
sandboxfs <name> detach <mountpoint>
sandboxfs <name> mount <local> <on_fs>
sandboxfs <name> mount
sandboxfs <name> umount <on_fs>
sandboxfs <name> hide <on_fs>
sandboxfs <name> protect-read <pattern>
sandboxfs <name> protect-write <pattern>
sandboxfs <name> protect-metadata <pattern>
sandboxfs <name> unprotect-read <pattern>
sandboxfs <name> unprotect-write <pattern>
sandboxfs <name> unprotect-metadata <pattern>
sandboxfs <name> passthrough-read <pattern>
sandboxfs <name> passthrough-write <pattern>
sandboxfs <name> passthrough-metadata <pattern>
sandboxfs <name> unpassthrough-read <pattern>
sandboxfs <name> unpassthrough-write <pattern>
sandboxfs <name> unpassthrough-metadata <pattern>
sandboxfs <name> list-protection [--read] [--write] [--metadata]
sandboxfs <name> list-passthrough [--read] [--write] [--metadata]
sandboxfs <name> chmod ...
sandboxfs <name> chown ...
sandboxfs <name> chattr ...
sandboxfs <name> allow [operation_id]
sandboxfs <name> allow <operation_id> [--path <sandbox-glob>] [--duration[=<duration>]] [--tree]
sandboxfs <name> allow --do-nothing <operation_id>
sandboxfs <name> deny <operation_id>
sandboxfs <name> cancel <operation_id>
sandboxfs <name> cancel-all [mountpoint]
sandboxfs <name> monitor [-f]
sandboxfs <name> metadata
sandboxfs-access-tui <name>
```

`mount` without arguments lists mappings and hide rules for the sandbox. `allow` without arguments lists pending authorization requests.

See also:

- [Concepts and lifecycle](concepts.md)
- [Policy, protection, passthrough, and grants](policy.md)
- [Metadata operations](metadata.md)
- [Logs, runtime paths, and limitations](runtime-and-limits.md)
