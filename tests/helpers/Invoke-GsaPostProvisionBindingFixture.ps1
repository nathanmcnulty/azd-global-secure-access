#Requires -Version 7.6
param(
    [Parameter(Mandatory)]
    [ValidateSet('subscriptionMismatch', 'tenantMismatch')]
    [string]$Case,
    [Parameter(Mandatory)]
    [string]$Root
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $Root 'scripts/modules/Gsa.Common.psm1') -Force
function Import-Module { param($Name, [switch]$Force) }
function Get-Module { param([switch]$ListAvailable, $Name) [pscustomobject]@{ Name = 'FixtureOnly' } }
function Assert-GsaCloudCapability { param($Capability, $Surface) }
function Get-GsaCloudCapability { param($AzureCloud, $GraphEnvironment) [pscustomobject]@{} }
function Get-GsaEnvironmentValue {
    param($Name, $Default, [switch]$Required)
    switch ($Name) {
        'AZURE_CLOUD_NAME' { 'AzureCloud' }
        'GSA_GRAPH_ENVIRONMENT' { 'Global' }
        'AZURE_TENANT_ID' { '11111111-1111-1111-1111-111111111111' }
        'AZURE_SUBSCRIPTION_ID' { '22222222-2222-2222-2222-222222222222' }
        default { $Default }
    }
}
function az {
    param([Parameter(ValueFromRemainingArguments)][object[]]$Arguments)
    $global:LASTEXITCODE = 0
    $subscriptionId = if ($Case -eq 'subscriptionMismatch') {
        '33333333-3333-3333-3333-333333333333'
    } else {
        '22222222-2222-2222-2222-222222222222'
    }
    $tenantId = if ($Case -eq 'tenantMismatch') {
        '33333333-3333-3333-3333-333333333333'
    } else {
        '11111111-1111-1111-1111-111111111111'
    }
    [pscustomobject]@{ id = $subscriptionId; tenantId = $tenantId } | ConvertTo-Json -Compress
}

$global:gsaFixtureConnects = 0
$global:gsaFixtureGraphReads = 0
function Connect-GsaGraph { param($Scopes, $Environment, $TenantId, $ExpectedAccount, [bool]$AllowInteractive); $global:gsaFixtureConnects++; throw 'FORBIDDEN_CONNECT' }
function Invoke-MgGraphRequest { $global:gsaFixtureGraphReads++; throw 'FORBIDDEN_DISPATCH' }
function Get-GsaTenantStatus { $global:gsaFixtureGraphReads++; throw 'FORBIDDEN_DISPATCH' }

$env:GSA_ENABLE_TENANT_ONBOARDING = 'true'
$failure = $null
try {
    & (Join-Path $Root 'scripts/Invoke-PostProvision.ps1')
} catch {
    $failure = $_.Exception.Message
}

if ($global:gsaFixtureConnects -ne 0 -or $global:gsaFixtureGraphReads -ne 0) {
    throw 'The post-provision fixture crossed the Graph boundary.'
}
[pscustomobject]@{
    failure = $failure
    graphConnects = $global:gsaFixtureConnects
    graphReads = $global:gsaFixtureGraphReads
} | ConvertTo-Json -Compress
