#Requires -Version 7.0

[CmdletBinding()]
param([string]$OutputPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modulePath 'Gsa.Common.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.Graph.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.State.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.RemoteNetwork.psm1') -Force

Assert-GsaPreviewGate -Feature 'Global Secure Access remote-network inventory' -Enabled $true
$azureCloud = Get-GsaEnvironmentValue -Name 'AZURE_CLOUD_NAME' -Default 'AzureCloud'
$graphEnvironment = Get-GsaEnvironmentValue -Name 'GSA_GRAPH_ENVIRONMENT' -Default 'Global'
$capability = Get-GsaCloudCapability -AzureCloud $azureCloud -GraphEnvironment $graphEnvironment
Assert-GsaCloudCapability -Capability $capability -Surface GraphCoreRead

$context = Connect-GsaGraph -Scopes @('NetworkAccess.Read.All', 'Policy.Read.All', 'LicenseAssignment.Read.All') -Environment $graphEnvironment
$remoteNetworks = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/connectivity/remoteNetworks' -Headers @{ Prefer = 'include-unknown-enum-members' })
foreach ($network in $remoteNetworks) {
    $links = @(Get-GsaGraphCollection -Uri "/beta/networkAccess/connectivity/remoteNetworks/$($network.id)/deviceLinks" -Headers @{ Prefer = 'include-unknown-enum-members' })
    $network | Add-Member -NotePropertyName deviceLinks -NotePropertyValue $links -Force
    if (-not $network.PSObject.Properties['forwardingProfiles']) { $network | Add-Member -NotePropertyName forwardingProfiles -NotePropertyValue @() }
}
$deployments = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/deployments' -Headers @{ Prefer = 'include-unknown-enum-members' })
$adaptiveAccess = Invoke-MgGraphRequest -Method GET -Uri '/beta/networkAccess/settings/conditionalAccess' -Headers @{ Prefer = 'include-unknown-enum-members' } -OutputType PSObject
$namedLocations = @(Get-GsaGraphCollection -Uri '/v1.0/identity/conditionalAccess/namedLocations')
$policies = @(Get-GsaGraphCollection -Uri '/v1.0/identity/conditionalAccess/policies')
$subscribedSkus = @(Get-GsaGraphCollection -Uri '/v1.0/subscribedSkus')
$licenseIndicators = Get-GsaRemoteNetworkLicenseIndicator -SubscribedSkus $subscribedSkus

$inventory = [pscustomobject][ordered]@{
    schemaVersion = '1.0.0'
    capturedAt = [DateTimeOffset]::UtcNow.ToString('O')
    tenantId = $context.TenantId
    azureCloud = $azureCloud
    graphEnvironment = $graphEnvironment
    remoteNetworks = $remoteNetworks
    deployments = $deployments
    adaptiveAccess = $adaptiveAccess
    namedLocations = $namedLocations
    conditionalAccessPolicies = $policies
    licenseCount = $licenseIndicators.conservativePurchasedSeatIndicator
    licenseIndicators = $licenseIndicators
    notes = @(
        'GET-only inventory. No router, connector, forwarding-profile association, or Adaptive Access change was attempted.',
        'Subscribed SKU inventory is advisory and cannot prove assignment, entitlement, or remote-network feature availability.'
    )
}
if ($OutputPath) { Write-GsaAtomicJson -Path $OutputPath -Value $inventory }
$inventory | ConvertTo-Json -Depth 100
