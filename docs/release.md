# Release and versioning guidance

This template uses Semantic Versioning while it remains pre-1.0. A minor version represents a material, reviewable expansion of template capability or safety contracts; a patch version represents compatible fixes or documentation corrections.

## Release checklist

1. Confirm `azure.yaml` `metadata.template`, the top entry in `CHANGELOG.md`, and the proposed Git tag use the same version.
2. Run the pinned PowerShell parser, PSScriptAnalyzer 1.25.0, Pester 5.7.1, Bicep, azd 1.30.0 isolated-environment, diff, and packaged-content checks.
3. Confirm tests and CI perform no live Azure, Entra, Graph, Intune, router, connector, or tenant deployment.
4. Review API maturity and supported-cloud statements against current official Microsoft documentation.
5. Review every committed fixture and sample for identifying values, credentials, private certificate material, and other secret-shaped content.
6. Merge the complete stack in order before tagging the resulting default-branch commit.
7. Create release notes from the changelog and identify beta/preview gates and production limitations prominently.

Do not publish when validation is incomplete, the stack is partially merged, API maturity is uncertain, or a live deployment is required to make the release appear successful. This repository intentionally has no automatic release workflow or credential-bearing publication job.

## Changelog policy

- Keep an `Unreleased` section for changes not yet tagged.
- Group entries under Added, Changed, Fixed, Security, Deprecated, or Removed as applicable.
- Describe safety boundaries and operator-visible behavior, not only implementation details.
- Never imply that a preview Graph API, diagnostic category, or tenant capability is generally available merely because a fixture or test covers its schema.
