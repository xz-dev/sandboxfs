# TODO

## Design xattr handling for sandboxfs

Extended attributes must not be blanket-passthrough. Some xattrs describe the backing host filesystem or host security context rather than the sandboxfs view, so exposing them unchanged can be inaccurate or unsafe. Examples include SELinux/security labels, capabilities, ACL-related attributes, and other `security.*`, `system.*`, or `trusted.*` namespaces.

Policy for the first xattr slice:

- only `user.*` xattrs are visible through sandboxfs;
- visible `user.*` xattrs are thin passthrough to the backing filesystem;
- `getxattr`/`listxattr` are metadata probes, not protected READ operations;
- `setxattr`/`removexattr` for `user.*` are thin passthrough host metadata mutations, because sandboxfs does not manage xattr overlays yet;
- non-`user.*` xattrs are filtered: `listxattr` omits them, `getxattr` reports them as absent, and `setxattr`/`removexattr` reject them as unsupported by sandboxfs policy;
- once an allowed `user.*` xattr operation reaches the backing filesystem, preserve the host filesystem's support and errno behavior.

Future work: revisit whether any non-`user.*` xattr namespace needs synthetic sandboxfs-specific values or sandbox-local overrides.
