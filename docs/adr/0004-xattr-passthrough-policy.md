# ADR 0004: Pass extended attributes through to the backing filesystem

## Status

Accepted.

## Context

Extended attributes are filesystem-specific metadata. Some xattrs, such as SELinux labels, file capabilities, ACL-related attributes, and other `security.*`, `system.*`, or `trusted.*` namespaces, may describe the backing host filesystem or host security context rather than a distinct sandboxfs context. Exposing those values through sandboxfs can therefore look odd or inaccurate from the sandbox namespace's point of view.

However, partially filtering, synthesizing, or emulating xattrs in sandboxfs would create a second behavior model that is likely to be less stable and less reproducible than the backing filesystem's behavior. sandboxfs already explicitly manages a small set of metadata surfaces such as mode, uid, gid, inode flags, and timestamps through sandbox-local policy/override handling. xattrs are not part of that managed surface.

## Decision

sandboxfs treats xattr operations as thin passthrough to the resolved backing filesystem path.

`getxattr` and `listxattr` are metadata probes, not protected READ operations. They resolve the sandbox namespace path, reject hidden or virtual-only paths as unavailable, then call the backing filesystem and preserve its support and errno behavior.

`setxattr` and `removexattr` are backing-host metadata mutations. Because sandboxfs does not manage xattr overlays, allowed xattr writes are not converted into sandbox-local overrides. They are forwarded to the backing filesystem and preserve its support and errno behavior.

sandboxfs does not filter, synthesize, or specially interpret `security.*`, `system.*`, `trusted.*`, SELinux, capability, ACL, or other xattr namespaces in this decision. Those values may reflect backing-host context, but host passthrough is reproducible. Partial sandboxfs emulation is more likely to produce unstable and surprising behavior.

If a future design wants any xattr namespace to become a sandboxfs-managed override, it must be introduced as an explicit managed metadata surface, like mode, uid, gid, flags, or timestamps. That is not part of the current design.

## Consequences

Tools that use xattrs observe backing filesystem behavior instead of fuser's default `ENOSYS` response.

Some xattr values may not describe an independent sandboxfs security context. This is accepted for the current design because sandboxfs is a namespace and authorization shim, not an LSM or xattr virtualization layer.

xattr behavior intentionally differs from sandboxfs-managed metadata overrides. Changes to mode, uid, gid, flags, and timestamps remain sandbox-local/policy-managed where implemented, while xattr mutations pass through to the host.
