# ADR 0004: Pass extended attributes through to the backing filesystem

## Status

Accepted.

## Context

Extended attributes are filesystem-specific metadata. Some xattrs, such as SELinux labels, file capabilities, ACL-related attributes, and other `security.*`, `system.*`, or `trusted.*` namespaces, may describe the backing host filesystem or host security context rather than a distinct gatefs context. Exposing those values through gatefs can therefore look odd or inaccurate from the sandbox namespace's point of view.

However, partially filtering, synthesizing, or emulating xattrs in gatefs would create a second behavior model that is likely to be less stable and less reproducible than the backing filesystem's behavior. gatefs already explicitly manages a small set of metadata surfaces such as mode, uid, gid, inode flags, and timestamps through sandbox-local policy/override handling. xattrs are not part of that managed surface, so xattr mutations need their own policy granularity rather than virtualization.

## Decision

gatefs treats xattr operations as forwarding to the resolved backing filesystem path after policy allows them.

`getxattr` and `listxattr` are xattr read probes. They resolve the sandbox namespace path, reject hidden or virtual-only paths as unavailable, then call the backing filesystem and preserve its support and errno behavior after policy allows them. They are governed by `protect-read`/`bypass-read` and by `protect-xattr`/`bypass-xattr`.

`setxattr` and `removexattr` are backing-host xattr mutations. Because gatefs does not manage xattr overlays, allowed xattr writes are not converted into sandbox-local overrides. They are forwarded to the backing filesystem and preserve its support and errno behavior. They are governed by `protect-write`/`bypass-write`, `protect-metadata`/`bypass-metadata`, and `protect-xattr`/`bypass-xattr`.

`protect-xattr` and `bypass-xattr` apply to the xattr surface: `getxattr`, `listxattr`, `setxattr`, and `removexattr`. They do not control chmod, chown, chattr, timestamp, file-content, or namespace effects.

`protect-metadata` and `bypass-metadata` remain mutation-oriented broader metadata controls. They continue to include `setxattr` and `removexattr`, but they do not gate `getxattr` or `listxattr`. `bypass-metadata` releases metadata protection for xattr mutations, but it does not release xattr-specific protection; `bypass-xattr` releases xattr-specific protection and can also release broad read/write/metadata protection for matching xattr operations.

gatefs does not filter, synthesize, or specially interpret `security.*`, `system.*`, `trusted.*`, SELinux, capability, ACL, or other xattr namespaces in this decision. Those values may reflect backing-host context, but host passthrough is reproducible. Partial gatefs emulation is more likely to produce unstable and surprising behavior.

If a future design wants any xattr namespace to become a gatefs-managed override, it must be introduced as an explicit managed metadata surface, like mode, uid, gid, flags, or timestamps. That is not part of the current design.

## Consequences

Tools that use xattrs observe backing filesystem behavior instead of fuser's default `ENOSYS` response.

Some xattr values may not describe an independent gatefs security context. This is accepted for the current design because gatefs is a namespace and authorization shim, not an LSM or xattr virtualization layer.

xattr behavior intentionally differs from gatefs-managed metadata overrides. Changes to mode, uid, gid, flags, and timestamps remain sandbox-local/policy-managed where implemented, while xattr mutations forward to the host after the relevant protection or bypass rule allows them.
