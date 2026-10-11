# Agent instructions

## Scope

This repository implements sandbox egress proxying, protocol middleware,
credential rewriting, and the local policy advisor.

## Working rules

- Treat destination resolution, SSRF defenses, TLS verification, policy
  enforcement, and credential handling as security boundaries.
- Preserve default-deny behavior. Review IPv4, IPv6, DNS changes, redirects, and
  proxy bypass behavior together when touching network decisions.
- Keep public policy behavior and limitations in sync with `cautem-core` and
  the security guide in `cautem-docs`.
- Keep local Go workspace replacements in the parent workspace's `go.work`,
  never in this repository's `go.mod`.

## Checks

- Run `go test ./...` from this checkout for Go changes.
- From the parent workspace, `task check` runs the shared Go gate.
