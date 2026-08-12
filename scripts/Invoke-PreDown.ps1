#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modulePath 'Gsa.Common.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.State.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.Cleanup.psm1') -Force

$manifestPath = Get-GsaStatePath
$pendingPath = Get-GsaStatePath -Pending
if (Test-Path -LiteralPath $pendingPath) {
    throw "A pending configuration transaction exists at '$pendingPath'. Resolve it before cleanup planning."
}
$manifest = Read-GsaStateManifest -Path $manifestPath
if (-not $manifest) {
    throw "No committed ownership manifest exists at '$manifestPath'. Cleanup authority cannot be inferred from names."
}

$observations = [ordered]@{}
$graphResources = @($manifest.resources | Where-Object { $_.kind -like 'Microsoft.Graph/*' -and $_.readUri })
$liveReads = Get-GsaBoolean -Value $env:GSA_PREDOWN_LIVE_GRAPH_READS
if ($liveReads -and $graphResources.Count -gt 0) {
    Assert-GsaPreviewGate -Feature 'Global Secure Access pre-down current-state inventory' -Enabled $true
    if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
        throw 'Install Microsoft.Graph.Authentication before enabling live pre-down Graph reads.'
    }
    $graphEnvironment = Get-GsaEnvironmentValue -Name 'GSA_GRAPH_ENVIRONMENT' -Default 'Global'
    $scopes = @('NetworkAccess.Read.All', 'NetworkAccessPolicy.Read.All', 'Policy.Read.All', 'Directory.Read.All', 'DeviceManagementConfiguration.Read.All')
    $context = Connect-GsaGraph -Scopes $scopes -Environment $graphEnvironment
    if ($context.TenantId -ne $manifest.environment.tenantId) {
        throw "Graph tenant '$($context.TenantId)' does not match manifest tenant '$($manifest.environment.tenantId)'."
    }
    foreach ($resource in $graphResources | Sort-Object key) {
        try {
            $current = Invoke-MgGraphRequest -Method GET -Uri $resource.readUri -Headers @{ Prefer = 'include-unknown-enum-members' } -OutputType PSObject
            $observations[$resource.key] = [ordered]@{
                objectId      = if ($current.PSObject.Properties['id']) { [string]$current.id } else { [string]$resource.id }
                classification = Compare-GsaResourceState -Resource $resource -Actual $current -ActualId $(if ($current.PSObject.Properties['id']) { $current.id } else { $resource.id })
                current       = $current
            }
        } catch {
            $observations[$resource.key] = [ordered]@{ objectId = $resource.id; classification = 'unobserved'; error = $_.Exception.Message }
        }
    }
}

foreach ($resource in @($manifest.resources | Sort-Object key)) {
    if (-not $observations.Contains($resource.key)) {
        $classification = if ($resource.kind -like 'Microsoft.Graph/*') { 'unobserved' } else { 'managed' }
        $observations[$resource.key] = [ordered]@{
            objectId       = $resource.id
            classification = $classification
            current        = if ($classification -eq 'managed') { $resource.observedState } else { $null }
        }
    }
}

$plan = Get-GsaCleanupPlan -Manifest $manifest -Observations $observations
$jsonPath = Get-GsaCleanupArtifactPath -Type cleanup -Format json
$textPath = Get-GsaCleanupArtifactPath -Type cleanup -Format txt
Write-GsaCleanupPlanArtifact -Plan $plan -JsonPath $jsonPath -TextPath $textPath

Write-Output (ConvertTo-GsaCleanupPlanText -Plan $plan)
Write-Information "Cleanup evidence written to '$jsonPath' and '$textPath'." -InformationAction Continue
Write-Information 'This hook performed no Microsoft Graph mutation. azd down will continue with Azure resource cleanup only.' -InformationAction Continue
