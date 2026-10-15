#Requires -Version 7.6
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$ScratchPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $Root 'scripts/modules/Gsa.Common.psm1') -Force
Import-Module (Join-Path $Root 'scripts/modules/Gsa.Readiness.psm1') -Force
function Import-Module { param($Name, [switch]$Force) }
function Get-Module { param([switch]$ListAvailable, $Name) [pscustomobject]@{ Name='FixtureOnly' } }
function Assert-GsaPreviewGate { param($Feature, $Enabled) }
function Get-GsaEnvironmentValue {
    param($Name, $Default)
    switch ($Name) {
        'AZURE_TENANT_ID' { return '11111111-1111-1111-1111-111111111111' }
        'GSA_CONNECTOR_GROUP_ID' { return '22222222-2222-2222-2222-222222222222' }
        default { return $Default }
    }
}
function Get-GsaStatePath { param([switch]$Pending) Join-Path $ScratchPath 'absent-state.json' }
function Read-GsaStateManifest { param($Path) return $null }
function Connect-GsaGraph {
    param($Scopes, $Environment, $TenantId)
    if ($TenantId -ne '11111111-1111-1111-1111-111111111111') { throw 'FORBIDDEN_TARGET' }
    [pscustomobject]@{ TenantId=$TenantId; Environment=$Environment; Scopes=$Scopes }
}
function Get-GsaTenantStatus {
    [pscustomobject]@{ onboardingStatus='onboarded'; onboardingErrorMessage='' }
}
$global:gsaEmptyReadinessCollections = [Collections.Generic.List[string]]::new()
function Get-GsaGraphCollection {
    param($Uri, $Headers)
    if ($Uri -notin @(
        '/beta/networkAccess/forwardingProfiles',
        '/beta/networkAccess/forwardingPolicies',
        '/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/22222222-2222-2222-2222-222222222222/members',
        '/v1.0/me/transitiveMemberOf?$select=id,displayName',
        '/v1.0/subscribedSkus',
        '/beta/networkAccess/deployments',
        '/beta/networkAccess/tls/externalCertificateAuthorityCertificates'
    )) { throw 'FORBIDDEN_COLLECTION' }
    $global:gsaEmptyReadinessCollections.Add($Uri)
    return @()
}
function Invoke-MgGraphRequest {
    param($Method, $Uri, $OutputType, $Headers)
    if ($Method -ne 'GET') { throw 'FORBIDDEN_MUTATION' }
    switch ($Uri) {
        '/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/22222222-2222-2222-2222-222222222222' { return [pscustomobject]@{ name='Fixture connector group' } }
        '/beta/networkAccess/settings/conditionalAccess' { return [pscustomobject]@{ signalingStatus='disabled' } }
        default { throw 'FORBIDDEN_DISPATCH' }
    }
}
function Connect-MgGraph { throw 'FORBIDDEN_AUTHENTICATION' }
function Connect-AzAccount { throw 'FORBIDDEN_AUTHENTICATION' }
function Publish-GsaCrl { throw 'FORBIDDEN_PUBLICATION' }
function Write-GsaAtomicJson { throw 'FORBIDDEN_WRITE' }
$env:GSA_ENABLE_TLS_INSPECTION = 'true'
$env:GSA_ENABLE_INTERNET_BASELINE = 'false'
& (Join-Path $Root 'scripts/Test-GsaReadiness.ps1') -JsonOnly
$entryExit = $LASTEXITCODE
if ($global:gsaEmptyReadinessCollections.Count -ne 7) { throw 'INCOMPLETE_FIXTURE' }
exit $entryExit
