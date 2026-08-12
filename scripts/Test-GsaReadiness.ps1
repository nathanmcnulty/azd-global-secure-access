#Requires -Version 7.0

[CmdletBinding()]
param(
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modulePath 'Gsa.Common.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.Graph.psm1') -Force

if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    throw 'Install Microsoft.Graph.Authentication before running readiness validation.'
}

Assert-GsaPreviewGate -Feature 'Global Secure Access readiness validation' -Enabled $true

$scopes = [System.Collections.Generic.List[string]]::new()
$scopes.Add('NetworkAccess.Read.All')
$connectorGroupId = Get-GsaEnvironmentValue -Name 'GSA_CONNECTOR_GROUP_ID'
if ($connectorGroupId) {
    # Graph currently requires this delegated scope even for connector-group GET operations.
    $scopes.Add('Directory.ReadWrite.All')
}
if (Get-GsaBoolean $env:GSA_ENABLE_INTERNET_BASELINE) {
    $scopes.Add('Policy.Read.All')
}

$graphContext = Connect-GsaGraph -Scopes @($scopes)
$azureTenantId = Get-GsaEnvironmentValue -Name 'AZURE_TENANT_ID'
if ($azureTenantId -and $graphContext.TenantId -ne $azureTenantId) {
    throw "Graph tenant '$($graphContext.TenantId)' does not match Azure tenant '$azureTenantId'."
}

$checks = [System.Collections.Generic.List[object]]::new()
function Add-GsaReadinessCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Warning', 'Fail', 'Info')][string]$Status,
        [Parameter(Mandatory)][string]$Detail
    )
    $checks.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail })
}

$tenantStatus = Get-GsaTenantStatus
$onboardingState = [string]$tenantStatus.onboardingStatus
Add-GsaReadinessCheck -Name 'Tenant onboarding' -Status $(if ($onboardingState -eq 'onboarded') { 'Pass' } else { 'Fail' }) -Detail "State: $onboardingState"

$forwardingProfiles = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/forwardingProfiles')
foreach ($trafficType in 'm365', 'private', 'internet') {
    $profileMatches = @($forwardingProfiles | Where-Object { $_.trafficForwardingType -eq $trafficType })
    if ($profileMatches.Count -eq 1) {
        Add-GsaReadinessCheck -Name "Forwarding profile: $trafficType" -Status 'Info' -Detail "State: $($profileMatches[0].state)"
    } else {
        Add-GsaReadinessCheck -Name "Forwarding profile: $trafficType" -Status 'Fail' -Detail "Expected one profile; found $($profileMatches.Count)."
    }
}

if ($connectorGroupId) {
    try {
        $group = Invoke-MgGraphRequest -Method GET -Uri "/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$connectorGroupId" -OutputType PSObject
        $connectors = @(Get-GsaGraphCollection -Uri "/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$connectorGroupId/members")
        $active = @($connectors | Where-Object { $_.status -eq 'active' })
        Add-GsaReadinessCheck -Name 'Private Access connector group' -Status $(if ($active.Count -gt 0) { 'Pass' } else { 'Fail' }) -Detail "Group: $($group.name); active connectors: $($active.Count); total connectors: $($connectors.Count)"
    } catch {
        Add-GsaReadinessCheck -Name 'Private Access connector group' -Status 'Fail' -Detail $_.Exception.Message
    }
} else {
    Add-GsaReadinessCheck -Name 'Private Access connector group' -Status 'Info' -Detail 'GSA_CONNECTOR_GROUP_ID is not configured.'
}

if (Get-GsaBoolean $env:GSA_ENABLE_INTERNET_BASELINE) {
    $policyName = Get-GsaEnvironmentValue -Name 'GSA_BASELINE_POLICY_NAME' -Default 'GSA POC Baseline Web Filtering'
    $profileName = Get-GsaEnvironmentValue -Name 'GSA_BASELINE_SECURITY_PROFILE_NAME' -Default 'GSA POC Baseline Security Profile'
    $caName = Get-GsaEnvironmentValue -Name 'GSA_BASELINE_CA_POLICY_NAME' -Default 'GSA POC Baseline Internet Access'
    foreach ($specification in @(
        @{ Name = 'Internet filtering policy'; Uri = '/beta/networkAccess/filteringPolicies'; Property = 'name'; Value = $policyName },
        @{ Name = 'Internet security profile'; Uri = '/beta/networkAccess/filteringProfiles'; Property = 'name'; Value = $profileName },
        @{ Name = 'Internet Conditional Access policy'; Uri = '/beta/identity/conditionalAccess/policies'; Property = 'displayName'; Value = $caName }
    )) {
        $escaped = $specification.Value.Replace("'", "''")
        $filter = [uri]::EscapeDataString("$($specification.Property) eq '$escaped'")
        $objects = @(Get-GsaGraphCollection -Uri "$($specification.Uri)?`$filter=$filter")
        Add-GsaReadinessCheck -Name $specification.Name -Status $(if ($objects.Count -eq 1) { 'Pass' } else { 'Fail' }) -Detail "Expected one object named '$($specification.Value)'; found $($objects.Count)."
    }
}

$failedChecks = @($checks | Where-Object Status -eq 'Fail')
$summary = [pscustomobject]@{
    TenantId    = $graphContext.TenantId
    GeneratedAt = [DateTimeOffset]::UtcNow
    Ready       = $failedChecks.Count -eq 0
    Checks      = $checks.ToArray()
}

$json = $summary | ConvertTo-Json -Depth 8
if ($OutputPath) {
    $resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $parent = Split-Path $resolvedOutputPath -Parent
    if ($parent -and -not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Set-Content -Path $resolvedOutputPath -Value $json -Encoding utf8NoBOM
}
$json

if (-not $summary.Ready) {
    exit 1
}
