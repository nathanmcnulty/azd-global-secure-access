# Agent guidance

Read [docs/agent-assisted-deployment.md](docs/agent-assisted-deployment.md) and [docs/technical-reference.md](docs/technical-reference.md) before assisting with deployment.

- Never use or recommend device-code authentication.
- Treat discovery, planning, Azure provisioning, tenant mutation, policy enforcement, and cleanup as separate authority boundaries.
- Verify Azure and Microsoft Graph account, tenant, cloud, subscription, scopes, target IDs, feature gates, and plan freshness before any authorized write.
- Do not infer ownership from a display name. Preserve reused and unmanaged objects.
- Never print or persist access tokens, credentials, certificate private material, pre-shared keys, or real `.azure` environment contents.
- Do not enable Graph beta features, forwarding, TLS inspection, broad Intune assignment, Conditional Access, remote-network execution, or tenant cleanup without explicit administrator approval.
- Prefer read-only readiness, Bicep preview, tests, and exact-ID receipts. Stop at authentication, consent, licensing, cloud-support, connector-health, or stale-plan blockers.
