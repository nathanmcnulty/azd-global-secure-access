# Microsoft Entra Global Secure Access azd template

This repository provisions the Azure foundation for a Microsoft Entra Global Secure Access (GSA) proof of concept and optionally configures selected Microsoft Graph surfaces through explicit, idempotent post-provision hooks.

The design separates:

- **Bicep**: Azure resource group, Premium Key Vault, CRL storage, Azure RBAC, and optional diagnostics, Defender for Key Vault, and Key Vault private endpoint.
- **PowerShell**: tenant state, traffic forwarding, Quick Access/Private Access, HSM-backed certificate and CRL lifecycle, Intune trusted roots, and an opt-in Internet filtering baseline.
- **Manual gates**: connector installation, certificate enablement, AOSP trusted-root deployment, and Graph operations whose permissions or behavior are not sufficiently documented for an unattended default.

> [!IMPORTANT]
> Most GSA `networkAccess` APIs remain Microsoft Graph **beta** as of August 2026. Microsoft states that beta APIs are not supported for production applications. This template requires `GSA_ACCEPT_GRAPH_BETA_TERMS=true` before any beta Graph operation and leaves every Graph mutation disabled by default.

## What is provisioned

### Azure infrastructure

- Premium Azure Key Vault
  - Azure RBAC authorization
  - 90-day soft delete
  - purge protection
  - no legacy access policies
  - deterministic Key Vault Certificates Officer and Key Vault Crypto User assignments
- StorageV2 account for the signed CRL
  - Shared Key disabled
  - anonymous blob access disabled
  - Microsoft Entra authorization preferred
  - TLS 1.2 minimum for HTTPS
  - HTTPS-only deliberately disabled so the signed CRL can be retrieved over HTTP
  - deterministic Storage Blob Data Owner and Storage Account Contributor assignments
- Optional Key Vault diagnostics to an existing Log Analytics workspace
- Optional Microsoft Defender for Key Vault subscription plan
- Optional Key Vault private endpoint using an existing subnet and private DNS zone

### Tenant and data-plane automation

- Read GSA tenant onboarding state
- Explicitly gated tenant onboarding attempt
- Enable or disable the Microsoft 365, Private Access, and Internet Access forwarding profiles
- Create or reuse Quick Access and Private Access applications with an existing connector group
- Normalize and idempotently add FQDN, DNS suffix, IPv4, IPv6, CIDR, port, and protocol segments
- Optionally assign Private Access applications to one pilot group
- Create a non-exportable, 4096-bit RSA-HSM root CA
- Publish and verify a Key Vault-signed CRL before requesting a GSA CSR
- Sign and upload the GSA subordinate CA certificate and chain
- Create/update Intune trusted-root profiles without replacing their existing assignments
- Optionally create a reviewed Internet Access web-category policy, custom security profile, and disabled Conditional Access policy
- Run read-only readiness validation that inventories onboarding, forwarding profiles, connector health, and managed Internet policy objects

## Safety defaults

- No policy is assigned to All Users or All Devices by default.
- No forwarding profile is changed unless its state is explicitly set to `Enabled` or `Disabled`.
- No connector or connector group is created. At least one active connector must already exist.
- Existing tenant objects are reused by deterministic name and type.
- Existing active GSA certificates are never deleted or replaced in place.
- Rotation creates or resumes a replacement and preserves the active certificate.
- Unknown and transitional Graph certificate status values are retained and surfaced.
- The CRL number always increases, even if the local clock moves backward.
- A custom CRL hostname must resolve and serve the exact CRL before its URL is embedded in a certificate.
- Broad Intune assignment remains gated by `GSA_ACKNOWLEDGE_LAB_MODE=true`; Internet filtering is created unassigned and disabled.
- `azd down` removes Azure resources only. Tenant objects are intentionally not deleted.

## Prerequisites

### Local tools

- [Azure Developer CLI](https://learn.microsoft.com/azure/developer/azure-developer-cli/install-azd)
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli)
- PowerShell 7.4 or later
- [Bicep](https://learn.microsoft.com/azure/azure-resource-manager/bicep/install), available through Azure CLI
- `Az.Accounts` for TLS/CRL operations
- `Microsoft.Graph.Authentication` for Graph operations
- Pester 5 for tests

```powershell
Install-Module Az.Accounts -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser
```

### Licensing and roles

The target tenant needs the licenses required by the GSA and Intune features you enable.

Typical delegated roles:

- Global Secure Access Administrator
- Application Administrator for Quick Access/Private Access
- Intune Administrator for trusted-root profiles
- Azure `Contributor` plus `User Access Administrator`, or `Owner`, at the deployment scope
- Security Admin when enabling Defender for Key Vault

### Microsoft Graph permissions

| Surface | Delegated permission |
|---|---|
| Tenant state, forwarding profiles, TLS, filtering | `NetworkAccess.ReadWrite.All` |
| Internet filtering Conditional Access policy | `Policy.ReadWrite.ConditionalAccess` |
| Quick Access/Private Access application | `Directory.ReadWrite.All` |
| Pilot app-role assignment | `AppRoleAssignment.ReadWrite.All` |
| Intune trusted roots | `DeviceManagementConfiguration.ReadWrite.All` |

The tenant onboarding action currently documents no supported OAuth permission. The portal is the default onboarding path.

### Connector prerequisite

Quick Access and Private Access require an existing connector group with at least one active connector. Connector installation is an external-host operation and cannot be completed by Bicep.

Current Microsoft guidance requires:

- connector version `1.5.3417.0` or newer;
- network connectivity from the connector host;
- the connector registered in the intended tenant and connector group.

Use the connector group object ID for `GSA_CONNECTOR_GROUP_ID`.

The provisioning workflow now verifies that the selected group contains at least one connector whose Graph status is `active`. It stops before creating or changing Private Access configuration when the group has no active connector.

## Configuration

Create an environment and set the organization name:

```powershell
azd auth login
az login
azd env new gsa-lab
azd env set GSA_ORGANIZATION_NAME Contoso
```

The pre-provision hook supplies safe defaults for:

- `AZURE_LOCATION=eastus`
- `AZURE_RESOURCE_GROUP=rg-<environment>-gsa`
- `GSA_ORGANIZATION_NAME=<environment>` when omitted
- `AZURE_PRINCIPAL_ID` and `AZURE_PRINCIPAL_TYPE` from the current Azure access token

### Core Azure values

| Variable | Default | Description |
|---|---|---|
| `AZURE_LOCATION` | `eastus` | Azure deployment region |
| `AZURE_RESOURCE_GROUP` | `rg-<env>-gsa` | Resource group name |
| `GSA_ORGANIZATION_NAME` | azd environment name | Certificate organization and naming input |
| `AZURE_PRINCIPAL_ID` | current token `oid` | Principal receiving data-plane roles |
| `AZURE_PRINCIPAL_TYPE` | inferred | `User`, `ServicePrincipal`, or `Group` |
| `GSA_ENABLE_DIAGNOSTICS` | `false` | Enable Key Vault diagnostics |
| `GSA_LOG_ANALYTICS_WORKSPACE_ID` | empty | Existing workspace resource ID |
| `GSA_ENABLE_DEFENDER_FOR_KEY_VAULT` | `false` | Enable the billable subscription plan |
| `GSA_ENABLE_PRIVATE_ENDPOINT` | `false` | Deploy Key Vault private endpoint |
| `GSA_PRIVATE_ENDPOINT_SUBNET_ID` | empty | Existing subnet resource ID |
| `GSA_PRIVATE_DNS_ZONE_ID` | empty | Existing `privatelink.vaultcore.azure.net` zone ID |
| `GSA_PRIVATE_ENDPOINT_LOCATION` | Azure deployment region | Region of the existing subnet/VNet |
| `GSA_ACKNOWLEDGE_PRIVATE_ENDPOINT_RUNNER_ACCESS` | `false` | Confirms the hook runner has private Key Vault reachability |

Defender for Key Vault changes subscription billing. Private endpoint mode disables Key Vault public network access; run `azd provision` and certificate operations from a host with the required VNet path and private DNS. Set `GSA_PRIVATE_ENDPOINT_LOCATION` when the existing subnet is not in `AZURE_LOCATION`.

### Graph feature gate and forwarding profiles

| Variable | Default | Description |
|---|---|---|
| `GSA_ACCEPT_GRAPH_BETA_TERMS` | `false` | Required for all current GSA Graph operations |
| `GSA_M365_PROFILE_STATE` | `Unchanged` | `Enabled`, `Disabled`, or `Unchanged` |
| `GSA_PRIVATE_PROFILE_STATE` | `Unchanged` | `Enabled`, `Disabled`, or `Unchanged` |
| `GSA_INTERNET_PROFILE_STATE` | `Unchanged` | `Enabled`, `Disabled`, or `Unchanged` |
| `GSA_ENABLE_TENANT_ONBOARDING` | `false` | Request onboarding after reading tenant state |
| `GSA_ALLOW_UNDOCUMENTED_TENANT_ONBOARDING` | `false` | Required because no OAuth permission is documented |

Graph `trafficForwardingType=m365` represents the visible Microsoft 365 traffic profile. The separate Microsoft Entra traffic profile is system-managed and cannot be independently changed. This template never relies on localized profile names; it resolves the profile by `trafficForwardingType`.

Example:

```powershell
azd env set GSA_ACCEPT_GRAPH_BETA_TERMS true
azd env set GSA_M365_PROFILE_STATE Enabled
azd env set GSA_PRIVATE_PROFILE_STATE Enabled
azd env set GSA_INTERNET_PROFILE_STATE Enabled
```

### Quick Access and Private Access

| Variable | Default | Description |
|---|---|---|
| `GSA_CONNECTOR_GROUP_ID` | empty | Required existing connector group ID |
| `GSA_PILOT_GROUP_ID` | empty | Optional group assigned the app's User role |
| `GSA_ENABLE_QUICK_ACCESS` | `false` | Configure a Quick Access application |
| `GSA_QUICK_ACCESS_NAME` | `GSA Quick Access` | Deterministic display name |
| `GSA_QUICK_ACCESS_DESTINATIONS` | empty | Semicolon-separated `type:value` destinations |
| `GSA_QUICK_ACCESS_PORTS` | `443` | Comma-separated ports or ranges |
| `GSA_QUICK_ACCESS_PROTOCOL` | `tcp` | `tcp`, `udp`, or `tcp,udp` |
| `GSA_ENABLE_PRIVATE_ACCESS_APP` | `false` | Configure a per-application Private Access app |
| `GSA_PRIVATE_ACCESS_NAME` | `GSA Private Access` | Deterministic display name |
| `GSA_PRIVATE_ACCESS_DESTINATIONS` | empty | Semicolon-separated destinations |
| `GSA_PRIVATE_ACCESS_PORTS` | `443` | Comma-separated ports or ranges |
| `GSA_PRIVATE_ACCESS_PROTOCOL` | `tcp` | `tcp`, `udp`, or `tcp,udp` |
| `GSA_ALLOW_ADDITIONAL_PRIVATE_ACCESS_SEGMENTS` | `false` | Preserve reviewed extra segments instead of failing on drift |
| `GSA_ALLOW_ADDITIONAL_ASSIGNMENTS` | `false` | Preserve reviewed extra app/Intune assignments instead of failing |

Destination examples:

```text
fqdn:app.contoso.local
dnsSuffix:.corp.contoso.local
ip:10.20.30.40
ip:10.20.0.0/16
ip:2001:db8::10/128
```

Single IP addresses are normalized to `/32` or `/128`. CIDRs are normalized to the network prefix. Single ports are normalized to `start-end`, so repeated deployments compare the same canonical segment tuple.

The template does not delete segments or assignments. If a managed application contains segments outside the desired configuration, or a pilot target has additional assignments, deployment fails for manual review. Set the corresponding `GSA_ALLOW_ADDITIONAL_*` value only after confirming the extra access is intentional.

```powershell
azd env set GSA_CONNECTOR_GROUP_ID 00000000-0000-0000-0000-000000000000
azd env set GSA_PILOT_GROUP_ID 11111111-1111-1111-1111-111111111111
azd env set GSA_ENABLE_QUICK_ACCESS true
azd env set GSA_QUICK_ACCESS_DESTINATIONS 'fqdn:app.contoso.local;ip:10.20.30.40'
azd env set GSA_QUICK_ACCESS_PORTS '443,3389'
```

Do not configure overlapping IP/CIDR destinations on multiple Private Access applications. GSA enforces overlap restrictions across applications.

### TLS inspection, CRL, and Intune

| Variable | Default | Description |
|---|---|---|
| `GSA_ENABLE_TLS_INSPECTION` | `false` | Run root CA, CRL, GSA certificate, and Intune workflow |
| `GSA_ROOT_CERTIFICATE_NAME` | `gsa-tls-root-ca` | Key Vault certificate name |
| `GSA_ROOT_CERTIFICATE_CN` | `Global Secure Access TLS Root CA` | Root subject CN |
| `GSA_TLS_CERTIFICATE_CN` | `Global Secure Access Inspection CA` | GSA subordinate subject CN |
| `GSA_CRL_CUSTOM_HOSTNAME` | empty | Optional public HTTP CRL hostname |
| `GSA_ROTATE_TLS_CERTIFICATE` | `false` | Stage a replacement while preserving the active certificate |
| `GSA_ALLOW_UNDOCUMENTED_CERTIFICATE_ENABLE` | `false` | Opt in to the portal-observed, undocumented status PATCH |
| `GSA_INTUNE_PLATFORMS` | modern platform list | Comma-separated platforms |
| `GSA_INTUNE_ASSIGNMENT_MODE` | `None` | `None`, `PilotGroup`, or `AllDevices` |
| `GSA_ACKNOWLEDGE_LAB_MODE` | `false` | Required for Intune All Devices assignment |

Supported automatic trusted-root types:

- Windows 10/11
- macOS
- iOS/iPadOS
- Android Enterprise Device Owner
- Android Enterprise Work Profile

Android Device Administrator is intentionally excluded. Android AOSP Device Owner is reported as a manual step because no validated standalone typed trusted-root Graph resource is currently documented.

`AssignmentMode=None` means the template does not add or remove assignments. Existing assignments are preserved. PilotGroup and AllDevices modes fail on additional assignment drift unless `GSA_ALLOW_ADDITIONAL_ASSIGNMENTS=true` is explicitly set.

Certificate enablement is manual by default because the Graph resource documents `status` as read-only:

1. Deploy the root to a pilot device group.
2. Verify trust on representative devices.
3. Enable the uploaded certificate in Entra admin center.
4. Confirm the service reports it active.
5. Test a narrowly scoped TLS inspection security profile.

The optional `GSA_ALLOW_UNDOCUMENTED_CERTIFICATE_ENABLE=true` path is for tenant-tested labs only.

### Internet Access baseline

| Variable | Default | Description |
|---|---|---|
| `GSA_ENABLE_INTERNET_BASELINE` | `false` | Create the gated beta policy/profile/CA chain |
| `GSA_BASELINE_POLICY_NAME` | `GSA POC Baseline Web Filtering` | Deterministic filtering-policy name |
| `GSA_BASELINE_BLOCKED_CATEGORIES` | `SocialNetworking` | Reviewed Graph category identifiers; friendly `Social Media` and `Social Networking` aliases are normalized |
| `GSA_BASELINE_SECURITY_PROFILE_NAME` | `GSA POC Baseline Security Profile` | Deterministic custom security-profile name |
| `GSA_BASELINE_SECURITY_PROFILE_PRIORITY` | `100` | Custom security-profile priority |
| `GSA_BASELINE_POLICY_LINK_PRIORITY` | `100` | Filtering-policy priority within the profile |
| `GSA_BASELINE_CA_POLICY_NAME` | `GSA POC Baseline Internet Access` | Deterministic Conditional Access policy name |

The module creates a block policy, links it to a custom enabled security profile, and creates a Conditional Access policy for the **All internet resources with Global Secure Access** application. The CA policy is deliberately `disabled` with empty user, group, and role targets. The profile therefore has no effect until an administrator reviews the policy, adds a pilot assignment, and enables it. The template never links this policy to the built-in tenant-wide baseline.

Managed objects are resolved by deterministic name. Compatible objects are reused. Duplicate names or incompatible actions, rules, categories, priorities, links, assignments, session controls, or CA state stop the run without deleting or rewriting tenant configuration. Category values must use the identifiers shown by the current GSA experience/API, such as `SocialNetworking`; the default blocks social-media sites through that documented category.

Custom Acquire/Bypass and Agentic Acquire rules remain portal/manual because Microsoft does not currently publish a complete validated REST workflow. Threat-intelligence defaults are also manual because Graph and portal examples disagree on `defaultAction`.

## Deploy

Review values:

```powershell
azd env get-values
```

Preview the Azure deployment:

```powershell
azd provision --preview
```

Provision Azure resources and run the post-provision hook:

```powershell
azd provision
```

The post-provision hook prompts for delegated Microsoft Graph consent when Graph features are enabled. TLS automation also requires an Az PowerShell context:

```powershell
Connect-AzAccount
azd provision
```

No real subscription or tenant deployment is performed by repository tests.

### Read-only readiness report

After setting the azd environment values, generate a tenant readiness report without making changes:

```powershell
azd env get-values | ForEach-Object {
    if ($_ -match '^([^=]+)="(.*)"$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2])
    }
}
pwsh ./scripts/Test-GsaReadiness.ps1 -OutputPath ./TestResults/gsa-readiness.json
```

The command performs only Graph GET operations, confirms the Graph and Azure tenant IDs match, inventories the three forwarding profiles, verifies the configured connector group has an active connector, and checks deterministic Internet baseline objects when that feature is enabled. It requests `NetworkAccess.Read.All` and, when applicable, `Policy.Read.All`. Connector-group reads currently require the delegated `Directory.ReadWrite.All` scope even though this command does not mutate directory objects. It exits nonzero for failed readiness checks so it can be used as a promotion gate.

## Validate

```powershell
az bicep build --file .\infra\main.bicep

$errors = @()
Get-ChildItem .\scripts -Recurse -Include *.ps1,*.psm1 | ForEach-Object {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $_.FullName,
        [ref]$tokens,
        [ref]$parseErrors
    ) | Out-Null
    $errors += $parseErrors
}
if ($errors) { $errors; throw 'PowerShell syntax validation failed.' }

Invoke-Pester .\tests -Output Detailed
```

The repository also runs these Bicep, PSScriptAnalyzer, and Pester checks in GitHub Actions for every pull request and push to `main`.

After deployment, validate:

1. Key Vault is Premium, RBAC-enabled, purge-protected, and reachable from the signing host.
2. Storage Shared Key and anonymous blob access are disabled.
3. The CRL returns HTTP 200, `application/pkix-crl`, and the expected byte length.
4. The GSA certificate is uploaded but the previous active certificate remains intact during rotation.
5. Trusted roots are assigned only to the intended pilot.
6. Forwarding profile state matches the explicit environment values.
7. Quick Access/Private Access segments and connector group match the intended configuration.
8. Pilot users can reach only intended destinations and ports.

## Custom CRL hostname

Before TLS provisioning, create a CNAME from the chosen host to the exact `GSA_CRL_WEB_ENDPOINT` hostname. Register the custom domain on the storage account if Azure Storage requires it for the host header.

```powershell
azd env set GSA_CRL_CUSTOM_HOSTNAME crl.contoso.com
```

The certificate workflow refuses to continue until:

- DNS resolves;
- `http://crl.contoso.com/gsa-tls-root-ca.crl` returns HTTP 200;
- the response content type is `application/pkix-crl`;
- the response length matches the newly signed CRL.

HTTP is intentional for revocation distribution. The CRL is signed by the HSM-backed CA, and using HTTPS for a certificate revocation endpoint can create a circular trust dependency.

## CRL renewal

The CRL defaults to a 30-day `nextUpdate`. Schedule renewal before expiration from a host with Key Vault and Storage data-plane access:

```powershell
Connect-AzAccount
.\scripts\Invoke-CrlRenewal.ps1 `
  -KeyVaultName '<GSA_KEY_VAULT_NAME>' `
  -StorageAccountName '<GSA_CRL_STORAGE_ACCOUNT_NAME>' `
  -WebEndpoint '<GSA_CRL_WEB_ENDPOINT>' `
  -RootCertificateName 'gsa-tls-root-ca'
```

The renewal script:

- reuses existing Azure resources;
- does not repeat the initial static-website service configuration;
- validates the RSA-HSM root;
- reads the previous public CRL state with Microsoft Entra authorization;
- serializes concurrent renewal runs with a renewable 60-second lease on a dedicated lock blob;
- chooses `max(current Unix milliseconds, previous + 1)`;
- signs with Key Vault;
- uploads with Microsoft Entra authorization;
- verifies public retrieval by exact SHA-256 content match.

It does not require Graph or modify GSA/Intune.

## Certificate rotation

1. Choose a new `GSA_ROOT_CERTIFICATE_NAME` if rotating the root.
2. Deploy the new root to pilot devices and verify it.
3. Set `GSA_ROTATE_TLS_CERTIFICATE=true`.
4. Run `azd provision`.
5. Enable the replacement in the portal after pilot trust is confirmed.
6. Verify the replacement is active and traffic succeeds.
7. Retire the old root only after the previous GSA certificate is no longer used.

The automation never deletes an active certificate. It resumes one safe pending `GSAKV*` certificate and fails if multiple pending objects or an unclassifiable transitional state exists.

## Cleanup

Remove Azure resources:

```powershell
azd down --purge
```

Purge protection prevents immediate permanent deletion of the Key Vault. Plan for the retention period.

Tenant cleanup is intentionally manual:

- restore forwarding profiles only when you have recorded their previous state;
- remove pilot app-role assignments;
- remove Quick Access/Private Access applications after confirming no dependent segments;
- unlink and remove the lab filtering policy;
- remove Intune trusted-root profiles only after all TLS-inspection certificates using the root are retired;
- disable or retire the GSA certificate in the portal.

The scripts do not perform destructive tenant-wide replacement or bulk cleanup.

## Client preparation

See [policies/README.md](policies/README.md) for reviewed Windows, macOS, iOS/iPadOS, and Android preparation. Client settings are not automatically imported because exported Settings Catalog policy IDs are tenant-specific and several platform payloads remain portal-managed.

At minimum:

- disable browser QUIC and Secure DNS/DoH for pilot validation;
- block outbound UDP/443 where needed so browsers do not bypass TCP acquisition;
- prefer IPv4 for scenarios not acquired over IPv6;
- install and validate the GSA client;
- deploy the root certificate before enabling TLS inspection.

## API support and limitations

| Surface | API | Template behavior |
|---|---|---|
| Tenant state | Graph beta | Read when Graph automation runs |
| Tenant onboarding | Graph beta, no documented OAuth permission | Portal by default; explicit double gate |
| Forwarding profiles | Graph beta | Idempotent, explicit state only |
| Microsoft Entra traffic profile | System-managed | Not changed |
| Quick Access/Private Access | v1.0 template plus beta publishing/segments | Explicit beta gate |
| Connector installation | External host | Prerequisite/manual |
| GSA TLS CSR/upload | Graph beta | Automated behind beta gate |
| GSA TLS enable | `status` documented read-only | Manual by default |
| Intune trusted roots | Primarily Graph beta | Five validated modern types |
| Android AOSP trusted root | No validated standalone typed resource | Manual |
| Internet web-category baseline | Graph beta | Custom profile plus disabled, unassigned CA policy |
| Custom/Agentic Acquire | Portal workflow | Manual |
| Threat intelligence baseline | Conflicting documented defaults | Manual |
| Conditional Access assignment | Graph beta session control; potential 60-90 minute propagation | Policy created disabled with no principals; pilot targeting and enablement require review |
| Readiness inventory | Graph beta plus CA reads; connector-group GET APIs currently require `Directory.ReadWrite.All` | Non-mutating report; optional CI or change-promotion gate |
| Traffic, deployment, and remote-network health logs | Graph beta and Microsoft Entra diagnostic settings | Documented monitoring target; no subscription-level diagnostic mutation by default |

Quick Access supports at most 500 segments, and nested group assignment is not supported. Security-profile and Conditional Access propagation can take 60-90 minutes.

## Production hardening

Before production use:

- replace delegated interactive execution with a reviewed automation identity where the API supports application permission;
- use Privileged Identity Management and time-bound Azure role activation;
- run private endpoint mode from a controlled management subnet;
- centralize Key Vault and Storage diagnostics;
- enable Defender only through the organization's subscription-security process;
- create alerting for Key Vault signing, certificate expiry, CRL expiry, and policy changes;
- export `NetworkAccessTraffic`, `RemoteNetworkHealthLogs`, `NetworkAccessAlerts`, audit logs, and deployment logs to the organization's Log Analytics/Sentinel workspace;
- use the built-in Global Secure Access Sentinel workbook and establish 30-day traffic and remote-network baselines before setting anomaly thresholds;
- use separate roots for environment or administrative boundaries;
- document certificate revocation and emergency bypass procedures;
- validate every beta Graph payload in a test tenant after SDK/API changes;
- replace lab category choices with approved security policy;
- use pilot rings and staged Conditional Access;
- maintain break-glass connectivity that does not depend on the inspected path;
- review client support for IPv6, QUIC, Secure DNS, and platform-specific prerequisites.

## Official references

- [Azure Developer CLI hooks](https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-extensibility)
- [azd environment variables](https://learn.microsoft.com/azure/developer/azure-developer-cli/manage-environment-variables)
- [Prevent Shared Key authorization for Azure Storage](https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent)
- [Azure Key Vault RBAC](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)
- [Azure Key Vault private link](https://learn.microsoft.com/azure/key-vault/general/private-link-service)
- [GSA traffic forwarding concepts](https://learn.microsoft.com/entra/global-secure-access/concept-traffic-forwarding)
- [GSA Private Access Graph tutorial](https://learn.microsoft.com/graph/tutorial-entra-private-access)
- [GSA Internet Access Graph tutorial](https://learn.microsoft.com/graph/tutorial-entra-internet-access)
- [GSA TLS inspection architecture](https://learn.microsoft.com/entra/global-secure-access/concept-transport-layer-security)
- [GSA TLS certificate settings](https://learn.microsoft.com/entra/global-secure-access/how-to-transport-layer-security-settings)
- [Graph external CA certificate API](https://learn.microsoft.com/graph/api/resources/networkaccess-externalcertificateauthoritycertificate?view=graph-rest-beta)
- [Intune trusted root profiles](https://learn.microsoft.com/intune/device-configuration/certificates-trusted-root-profiles)
- [GSA client deployment planning](https://learn.microsoft.com/entra/global-secure-access/how-to-install-windows-client)

## License

This project is released under the [Unlicense](LICENSE).
