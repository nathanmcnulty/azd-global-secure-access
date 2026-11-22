# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting channel for this repository. Do not open a public issue containing tenant IDs, access tokens, certificates, pre-shared keys, or other secrets. If private reporting is unavailable, contact the repository owner privately before disclosing details.

## Supported versions

This proof of concept has no published release or tag. The current default `main` branch is the only supported line for security fixes. Pre-release snapshots and other branches do not receive guaranteed fixes.

## Response targets

The maintainer aims to acknowledge a private report within 7 calendar days and provide an initial triage or next-steps decision within 14 calendar days. These are targets, not a guarantee of emergency staffing or remediation time.

## Safe disclosure

Keep vulnerability details private until impact has been assessed and a fix, mitigation, or coordinated disclosure decision is available. Do not publish tenant identifiers, connector details, access tokens, certificates, private keys, pre-shared keys, ownership manifests, readiness reports, `.azure` environment state, or unredacted deployment output in public issues, pull requests, examples, or release bundles.

## Deployment boundaries

This proof of concept can change Azure and Microsoft Entra tenant state. Use a dedicated pilot, least-privilege identities, staged Conditional Access, and break-glass connectivity that does not depend on the inspected path. Review ownership evidence and every explicit feature gate before approving tenant mutations.

## Secret handling

Never commit bearer tokens, private keys, certificates, pre-shared keys, or `.azure` environment state. Treat ownership manifests and readiness reports as sensitive administrative evidence.
