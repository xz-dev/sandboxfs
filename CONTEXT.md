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
