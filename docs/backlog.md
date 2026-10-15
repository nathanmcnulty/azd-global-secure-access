# Backlog: nathanmcnulty/azd-global-secure-access

> Generated from `docs/backlog.json`. Edit the JSON source and regenerate this file.
> Standard: [azd agent backlog standard](https://github.com/nathanmcnulty/azd-reference/blob/main/standards/agent-backlogs.md). This link is review guidance, not a runtime dependency.

- **Schema version:** 1.0.0
- **Repository:** nathanmcnulty/azd-global-secure-access
- **Source revision:** `859d4ca38e456964e297250fdcd3c0f19c7dff21`
- **Captured:** 2026-10-04
- **Items:** 4

## GSA-001: Reconcile this backlog with current source and active work

- **Kind:** discovery
- **Priority:** P1
- **Status:** done
- **Wave:** 0
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Plans and implementation evidence are spread across files; the captured source can change while other tasks work.

**Scope:**

- docs/backlog.json
- docs/backlog.md
- Existing roadmap, execution status, open issues and pull requests &lpar;read-only&rpar;

**Acceptance:**

- Classify each candidate as implemented, still open, superseded or awaiting evidence; retain source links and reasons.
- Inspect dirty state, remotes, worktrees and local environment presence without reading secrets; avoid duplicate work with active owners.
- Resolve the actual offline validation commands and record exact current default-branch/working-tree provenance; do not copy historical live passes to newer code.

**Validation:**

- git status --short
- git remote -v
- git worktree list --porcelain
- Read the applicable instructions and validation workflow; read gh issue list and gh pr list for the named repository using nathanmcnulty. Do not create or modify issues/PRs.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- README.md

**Evidence:**

- 2026-10-04 read-only reconciliation against current main 859d4ca38e456964e297250fdcd3c0f19c7dff21&colon; inspected canonical dirty state, remotes, worktrees and environment-path presence without reading values; active/unowned branches remain untouched. Reviewed current issue/PR inventory, roadmap/TODO task sources and .github/workflows/validate.yml; kept live and optional-feature gates proposed.
- Invoke-Pester ./tests -CI&colon; 113/113 passed, including missing/mismatched Azure tenant binding cases. Validation used offline fixtures only; no cloud, tenant, recipient or endpoint action was performed.

**Review and authorization note:**

Review GSA-001 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## GSA-004: Fail closed on missing Azure tenant before cached Graph mutation

- **Kind:** discovery
- **Priority:** P1
- **Status:** done
- **Wave:** 0
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Open report captured 2026-10-03 during execution reconciliation. Another code-quality task may own an active fix; inspect its PR and current source before dispatch.

**Scope:**

- Linked issue and current source &lpar;read-only&rpar;
- Repository-local backlog evidence

**Acceptance:**

- Read the linked issue and current default branch; classify the exact defect, current owner and evidence gap.
- Record a current PR or verified resolution before selecting any implementation; preserve broader feature and live acceptance gates.

**Validation:**

- Read current issue and PR state using nathanmcnulty; do not modify or close issues during reconciliation.
- Inspect dirty state and worktrees; resolve the exact current revision and relevant offline commands before implementation.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- https&colon;//github.com/nathanmcnulty/azd-global-secure-access/issues/14

**Evidence:**

- Source implementation is present in current main 859d4ca38e456964e297250fdcd3c0f19c7dff21; resolved revision 859d4ca38e456964e297250fdcd3c0f19c7dff21 via merged https&colon;//github.com/nathanmcnulty/azd-global-secure-access/pull/15.
- Invoke-Pester ./tests -CI&colon; 113/113 passed, including missing/mismatched Azure tenant binding cases. This completes only the bounded source/fixture acceptance; live-service, recovery, release and endpoint gates remain separate.

**Review and authorization note:**

Review GSA-004 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## GSA-002: Qualify the read-only readiness and exact-feature pilot

- **Kind:** verification
- **Priority:** P1
- **Status:** proposed
- **Wave:** 2
- **Authorization:** tenant-write
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Licensing, connectors, cloud support and Graph beta mutations remain feature-specific gates.

**Scope:**

- docs/technical-reference.md
- scripts/
- tests/

**Acceptance:**

- Record readiness, connector health and stale-plan rejection before authorizing one named feature.
- Test exact-ID rollback and reused-object preservation for that feature.
- TLS, forwarding, remote networks, CA and Intune assignments remain independent approvals with no broadened scope.

**Validation:**

- Use the offline commands in the registered validation workflow; record the exact commands, revision and results before implementation is complete.
- Run focused tests for changed behavior from tests/; fixtures do not prove live-service or endpoint behavior.
- After separate authorization, retain redacted exact-target live evidence and cleanup results outside public Git. Do not execute live operations from this backlog alone.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- AGENTS.md
- docs/technical-reference.md

**Evidence:**

- _none_

**Review and authorization note:**

Review GSA-002 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## GSA-003: Evaluate shared auth/validation and CRL health reporting

- **Kind:** discovery
- **Priority:** P2
- **Status:** proposed
- **Wave:** 2
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Graph session reuse and optional TLS/CRL state can be represented consistently without sharing policy mutation logic.

**Scope:**

- scripts/
- infra/
- docs/
- azd-components.lock.json

**Acceptance:**

- Compare delegated Graph coordinator only with a compatible Microsoft.Graph.Authentication session; do not replace unrelated Azure CLI flows.
- Report exact target/licensing/connector and optional CRL expiry status using bounded validation.
- TLS renewal or central alert sending is never executed by a read-only health check.

**Validation:**

- Use the offline commands in the registered validation workflow; record the exact commands, revision and results before implementation is complete.
- Run focused tests for changed behavior from tests/; fixtures do not prove live-service or endpoint behavior.

**Dependencies:**

- _none_

**Components:**

- graph-delegated-authentication
- deployment-validation
- azure-monitor-scheduled-query-notifications

**Sources:**

- README.md

**Evidence:**

- Partial CRL correctness/privacy improvement&colon; publication verification derives from validated committed and downloaded SHA-256 fingerprints, ignoring caller hashMatches. CRL DTOs omit URL/provider errors/unknown fields. Legacy nextUpdate remains normalized committed metadata with nextUpdateSource=committedState; observedNextUpdate is null and expiryObserved=false. Recorded expired/near dates retain Fail/Warning; future recorded dates remain advisory Warning, not observed-expiry Pass. Other readiness DTOs and ready=no-Fail semantics, public HTTP CDP, renewal/auth/infra/defaults remain unchanged. A minimal adjacent array normalization preserves empty Internet-baseline results so readiness reaches the CRL check. PowerShell 7.6.6 full141 tests/28 new cases, analyzer Error+Warning, parse/Bicep/package/local azd-load gates pass; no live readiness/renewal/grant/alert execution.
- Bounded CRL transport closes the selected GSA-003 download gap&colon; the read-only entrypoint uses one direct anonymous no-redirect HttpClient request with ambient proxies disabled, a 15-second total header/body deadline and 1 MiB streaming limit. Only a complete nonempty HTTP 200 application/pkix-crl body is hashed; malformed or credential-bearing locations, redirects, invalid media/status, oversized, truncated and timed-out bodies fail to the existing closed DTO without URL or provider error details. Focused PowerShell 7.6.6 tests pass 44/44, including real loopback transport, credentialed ambient-proxy bypass and actual entrypoint wiring, and changed production scripts pass PSScriptAnalyzer 1.25.0 Error+Warning with zero findings. Public HTTP CDP, renewal, publication, auth, infrastructure and defaults remain unchanged; no live readiness/renewal/grant/alert execution occurred. GSA-003 remains proposed because its broader authentication, target, licensing and connector acceptance is not closed.

**Review and authorization note:**

Review GSA-003 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.
