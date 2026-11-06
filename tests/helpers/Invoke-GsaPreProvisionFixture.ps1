#Requires -Version 7.6
param(
    [Parameter(Mandatory)][string]$Root,
    [string]$ProfileName = 'GSA_M365_PROFILE_STATE',
    [string]$ProfileState = 'Unchanged',
    [string]$FeatureName,
    [switch]$EmptyProfiles,
    [switch]$LowercaseProfiles,
    [switch]$AcceptBeta
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Isolate the real hook from inherited configuration and external CLI calls.
foreach ($variable in @(Get-ChildItem Env:GSA_*)) {
    Remove-Item -LiteralPath "Env:$($variable.Name)"
}
foreach ($line in Get-Content (Join-Path $Root 'samples/azd-safe-poc.env')) {
    if ($line -match '^([A-Z][A-Z0-9_]+)="([^"]*)"$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2])
    }
}
$env:AZURE_ENV_NAME = 'fixture'
$env:AZURE_LOCATION = 'eastus'
$env:AZURE_RESOURCE_GROUP = 'rg-fixture'
$env:AZURE_PRINCIPAL_ID = '33333333-3333-3333-3333-333333333333'
$env:AZURE_PRINCIPAL_TYPE = 'User'
$env:AZURE_CLOUD_NAME = 'AzureCloud'
$env:GSA_GRAPH_ENVIRONMENT = 'Global'
$env:GSA_ORGANIZATION_NAME = 'Fixture'
foreach ($name in @('GSA_M365_PROFILE_STATE', 'GSA_PRIVATE_PROFILE_STATE', 'GSA_INTERNET_PROFILE_STATE')) {
    if ($EmptyProfiles) { [Environment]::SetEnvironmentVariable($name, '') }
    elseif ($LowercaseProfiles) { [Environment]::SetEnvironmentVariable($name, 'unchanged') }
}
if (-not $EmptyProfiles -and -not $LowercaseProfiles) {
    [Environment]::SetEnvironmentVariable($ProfileName, $ProfileState)
}
if ($FeatureName) { [Environment]::SetEnvironmentVariable($FeatureName, 'true') }
if ($AcceptBeta) { $env:GSA_ACCEPT_GRAPH_BETA_TERMS = 'true' }

$global:gsaPreProvisionFixtureCloudReads = 0
function az {
    param([Parameter(ValueFromRemainingArguments)][object[]]$Arguments)
    if ($Arguments.Count -ne 6 -or $Arguments[0] -cne 'cloud' -or $Arguments[1] -cne 'show') {
        throw 'Unexpected external Azure command in preprovision fixture.'
    }
    $global:gsaPreProvisionFixtureCloudReads++
    $global:LASTEXITCODE = 0
    '{"name":"AzureCloud","resourceManager":"https://management.azure.com/"}'
}
function azd { throw 'Unexpected environment mutation in preprovision fixture.' }

$failure = $null
try { & (Join-Path $Root 'scripts/Invoke-PreProvision.ps1') *>&1 | Out-Null }
catch { $failure = $_.Exception.Message }
[pscustomobject]@{ failure = $failure; cloudReads = $global:gsaPreProvisionFixtureCloudReads } | ConvertTo-Json -Compress
