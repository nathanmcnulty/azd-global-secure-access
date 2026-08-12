# Architecture and lifecycle diagrams

These Mermaid sources are the reviewable source of truth. An image exported from the architecture diagram can be added later for an Awesome AZD gallery submission, but the repository does not depend on an opaque binary artifact.

## Architecture and trust boundaries

```mermaid
flowchart LR
  Operator[Operator workstation] -->|azd and reviewed PowerShell| Azure[Azure subscription]
  Operator -->|delegated, explicitly gated requests| Graph[Microsoft Graph]
  Azure --> KV[Premium Key Vault]
  Azure --> CRL[CRL storage]
  Azure -. optional existing destination .-> LAW[Existing Log Analytics workspace]
  Graph --> GSA[Global Secure Access tenant surfaces]
  Graph --> Intune[Intune configuration evidence]
  Router[External CPE router] -. manual configuration only .-> GSA
  Connector[External connector host] -. manual installation and registration .-> GSA
  State[Local ignored azd ownership state] -->|exact IDs only| Operator
```

## Deployment lifecycle

```mermaid
flowchart TD
  Inputs[Conservative azd inputs] --> Pre[preprovision validation]
  Pre --> Preview[Azure preview or reviewed provision]
  Preview --> Bicep[Bicep Azure resources]
  Bicep --> Gate{Graph features explicitly enabled?}
  Gate -- no --> Report[Readiness and evidence reports]
  Gate -- yes --> Pending[Write pending transaction]
  Pending --> Mutate[Only documented and gated operations]
  Mutate --> Commit[Atomic committed manifest]
  Mutate -->|failure| Reconcile[Keep prior commit and pending evidence]
```

## Ownership transaction

```mermaid
stateDiagram-v2
  [*] --> Unclaimed
  Unclaimed --> Pending: write operation ID and desired fingerprint
  Pending --> Committed: all enabled operations succeed and exact IDs return
  Pending --> ReconciliationRequired: interruption or partial failure
  Committed --> Pending: later reviewed change
  Committed --> Reused: never; names cannot transfer ownership
  ReconciliationRequired --> Pending: operator reconciles current state
```

The committed manifest is the sole ownership authority. Display names, natural identifiers, and matching configuration never adopt an object.

## Cleanup and recovery

```mermaid
flowchart TD
  Manifest[Committed exact-ID manifest] --> Observe[Optional GET-only current-state evidence]
  Observe --> Plan[Deterministic JSON and text cleanup plan]
  Plan --> Down[Ordinary azd down removes Azure resources]
  Plan -. no Graph mutation .-> Preserve[Preserve reused, unmanaged, active, stale, or ambiguous tenant objects]
  Outage[Forwarding outage] --> RecoveryPlan[Expiring recovery plan]
  RecoveryPlan --> Ack[Exact plan ID plus traffic-impact acknowledgement]
  Ack --> StateCheck[Re-read exact profile IDs and states]
  StateCheck --> Apply[Change forwarding state only]
  Apply --> Audit[Sanitized audit artifact and captured-state restore plan]
```

## Observability and client evidence

```mermaid
flowchart LR
  Discover[Discover tenant diagnostic categories] --> Inventory[Capture settings and available tables]
  Inventory --> Plan[Deterministic existing-workspace plan]
  Plan --> Preserve[Preserve unmanaged routes]
  Plan --> Assets[Schema-tolerant KQL, workbooks, disabled alerts]
  Client[Sanitized endpoint and Intune evidence] --> Readiness[JSON and text readiness]
  Assets --> Readiness
  Readiness --> Limits[Evidence is partial; assignment is not acquisition or health]
```

## Remote networks and Adaptive Access

```mermaid
flowchart TD
  Get[GET-only inventory] --> Validate[Cloud, license, IP, BGP, crypto, NAT, redundancy validation]
  Validate --> Risk[Microsoft and Internet association traffic-loss analysis]
  Risk --> Plan[Deterministic stale-checked plan]
  Plan --> Eligible{New unclaimed network and first link only?}
  Eligible -- no --> Manual[Report or manual action]
  Eligible -- yes --> Ack[Exact acknowledgement, Execute, pending state]
  Ack --> Create[Graph beta create operations]
  Create --> Commit[Commit exact returned IDs]
  Router[Router and connector changes] --> Manual
  Adaptive[Source-IP, compliant-network, named location, CA, Universal CAE] --> Manual
```

## Validation and release lifecycle

```mermaid
flowchart LR
  Change[Reviewed source change] --> Parser[PowerShell parser]
  Parser --> Analyzer[PSScriptAnalyzer 1.25.0]
  Analyzer --> Tests[Pester 5.7.1]
  Tests --> Bicep[Bicep build]
  Bicep --> Azd[Isolated azd 1.30.0 load]
  Azd --> Audit[Diff and packaged-content audit]
  Audit --> PR[Stacked pull request]
  PR --> CI[Non-deploying GitHub Actions]
  CI --> Release[Manual version and changelog decision]
```
