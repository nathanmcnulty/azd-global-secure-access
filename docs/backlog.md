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
- Bounded Graph pagination closes the selected GSA-003 continuation gap&colon; every initial and continuation location is bound to the current known Graph cloud HTTPS origin and exact collection path before dispatch, opaque locations and caller headers are forwarded unchanged, malformed collection envelopes, cycles and malformed links fail closed, and complete results are buffered behind default 100-page/10,000-item limits with declared override maxima. All 35 production call sites use collection endpoints, so non-collection response fallback was removed. Focused PowerShell 7.6.6 Common+Graph tests pass 55/55 and changed production code passes PSScriptAnalyzer 1.25.0 Error+Warning with zero findings. The graph-delegated-authentication 0.1.1 comparison is pinned to azd-reference revision d4d2fee7440b2dc700d2e7898cc0c932b9300314; its explicit tenant/account/probe/interaction contract remains separate unresolved work. No authentication, consent, scope, SDK retry/timeout, mutation or runtime dependency changed, and no live Graph request occurred. GSA-003 remains proposed.
- Explicit Graph tenant binding closes the selected GSA-003 target-selection gap&colon; all six callers supply an existing configured or committed tenant, and Connect-GsaGraph validates a nonzero tenant GUID before reading context. A cached context is reused only for the same tenant and cloud; mismatch fails before login, consent or Graph reads. Normal browser authentication receives the normalized target tenant GUID when context or scopes are absent, followed by tenant, cloud and scope verification. Readiness records Fail and performs no Graph interaction for a missing or malformed AZURE&lowbar;TENANT&lowbar;ID instead of claiming tenant consistency. Focused PowerShell 7.6.6 tenant/Common/CRL entrypoint and transport tests pass 114/114. Post-provision now rejects a configured subscription or tenant mismatch against Azure CLI before Graph connection or scope consent, while retaining the post-connect Graph tenant comparison; focused ordering tests pass 24/24 with zero Graph connects or dispatches for both mismatch cases. Existing manifest and subscription guards remain, no scopes or SDK dependencies changed, and no live login, consent, probe, Graph read or mutation occurred. Broader expected-account and probe qualification remains open, so GSA-003 remains proposed.
- Empty readiness observations are now handled without parameter-binding aborts across license, role, connector, certificate, traffic-rule and deployment checks. Missing connectors and requested/committed TLS certificates fail; absent license/role indicators, traffic rules and deployment history warn without asserting success. Null observations remain rejected. PowerShell 7.6.6 focused validation passed 21/21, including the actual read-only entrypoint with all seven supported collection responses empty. No live Graph, authentication, renewal, grants or alerts ran; broader GSA-003 qualification remains open.
- Explicit delegated account and session-usability preflight&colon; all six maintained Graph callers supply GSA&lowbar;GRAPH&lowbar;EXPECTED&lowbar;ACCOUNT and default-off GSA&lowbar;GRAPH&lowbar;ALLOW&lowbar;INTERACTIVE. The helper enforces beta acceptance before context or authentication and requires matching delegated account, tenant, cloud, scopes and known Process/CurrentUser context; incompatible cached contexts stop before login or reads. Explicitly authorized login requests CurrentUser and is revalidated; a fixed forwardingProfiles GET uses existing NetworkAccess permissions, discards its result and fails closed without login fallback. Canonical graph-delegated-authentication 0.1.1 comparison remains pinned to d4d2fee7440b2dc700d2e7898cc0c932b9300314 without adoption or Azure CLI changes. PowerShell 7.6.6/Pester 6.2.0 offline validation passed 254/254; no live authentication, consent, Graph request or tenant mutation occurred. GSA-003 remains proposed for native account/session, licensing and connector qualification. Refs issue &num;25.
- Validation-integrity follow-up&colon; CI now requires a nonempty all-passing Pester suite and rejects skipped, inconclusive or unexecuted cases. Actual original/corrected workflow blocks ran on PowerShell 7.6.6/Pester 6.2.0 against six isolated outcome fixtures&colon; the original accepted inconclusive-only and all-skipped runs, while the corrected block accepts only the passing fixture. Product scripts, test cases, SDK dependencies and scopes remain unchanged. Native GSA qualification remains open.
- Observed CRL expiry closes the selected GSA-003 date-source gap&colon; the bounded downloader structurally validates completed DER bytes, hashes those exact bytes, and extracts RFC 5280 thisUpdate/nextUpdate. Missing, malformed, trailing, inverted, future-effective, and expired observations fail closed; committed expiry remains a labelled advisory and cannot mask observed expiry. Current observed dates remain Warning because signature and issuer trust are explicitly unverified. Focused PowerShell 7.6.6 Pester 5.7.1 validation passed 53/53 with real signed UTCTime and GeneralizedTime loopback fixtures plus actual entrypoint wiring. No live publication, authentication, renewal, mutation, signature verification, or issuer verification occurred; broader GSA-003 account/probe qualification remains open.
- Baseline current-main reconciliation on 2026-10-18 merges main 873664b4f03548dff0af62e66cf4a2d8dbd40a51, including merged PR &num;24 observed DER CRL expiry. The CRL module and its test/helper logic retain current-main bytes; the readiness entrypoint differs only in its owned PowerShell 7.6 declaration. Current authoring/test guidance and the existing baseline migration remain intact. Full PowerShell 7.6.6/Pester 6.2.0 validation passes 242/242 with zero failed, skipped, inconclusive or unexecuted tests; all scripts pass Error/Warning analysis. The already reviewed strict Pester outcome gate is lifted into the baseline workflow. No permission, SDK, renewal, transport-default or authentication-route change occurred; native GSA-003 qualification remains open.

**Review and authorization note:**

Review GSA-003 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.
