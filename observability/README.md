# Observability source assets

Run `scripts/New-GsaObservabilityPlan.ps1` with a sanitized read-only inventory captured from the target tenant and workspace. The generated assets are source material, not an automatic deployment. They remain disabled until an operator confirms that the tenant exposed the requested category, the destination is the explicitly supplied existing workspace, the expected table has ingested data, and a useful baseline exists.

The generated KQL uses `union isfuzzy=true`, `column_ifexists()`, and explicit string/date normalization so absent or evolving columns do not become success-shaped defaults. Missing tables or empty results are inconclusive, not healthy. Default queries expose aggregate counts, status, and timestamps; browsing URLs, prompt content, user principal names, and source IP addresses are excluded.

Microsoft Entra diagnostic settings use the tenant-scoped `Microsoft.AADIAM/diagnosticSettings` resource mechanism. Global Secure Access category maturity varies, and preview categories are enabled only when discovery evidence shows that the tenant currently exposes them. Existing unmanaged routes are inventory only and are never replaced, deleted, or adopted by name.
