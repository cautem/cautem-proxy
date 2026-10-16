# Roadmap — cautem-proxy

Status: **v0.3.0** (release prepared) · Depends on core `v0.3.0`; slogx `v0.1.3`

## This module

| ID | Item | Notes |
|----|------|-------|
| X1 | **JWT verify** | Cryptographic JWKS/HMAC before credential rewrite |
| X2 | **Secret backends** | Bridge Vault/cloud SM into sidecar `SecretStore` |
| X3 | **policy.local ↔ gateway** | Reliable proposal sync when gateway is present |
| X4 | **MCP terminate** | Policy-aware MCP frames |

## Release

Requires cautem-core `v0.3.0` · tagged after core in the release cascade.
