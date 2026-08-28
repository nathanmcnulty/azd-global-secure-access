# Security

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting channel for this repository. Do not open a public issue containing tenant IDs, access tokens, certificates, pre-shared keys, or other secrets. If private reporting is unavailable, contact the repository owner privately before disclosing details.

## Deployment boundaries

This proof of concept can change Azure and Microsoft Entra tenant state. Use a dedicated pilot, least-privilege identities, staged Conditional Access, and break-glass connectivity that does not depend on the inspected path. Review ownership evidence and every explicit feature gate before approving tenant mutations.

## Secret handling

Never commit bearer tokens, private keys, certificates, pre-shared keys, or `.azure` environment state. Treat ownership manifests and readiness reports as sensitive administrative evidence.
