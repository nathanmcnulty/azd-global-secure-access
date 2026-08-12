#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'modules\Gsa.Common.psm1') -Force

function Initialize-AzdEnvironmentValue {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )

    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($Name))) {
        & azd env set $Name $Value | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to set azd environment value '$Name'."
        }
        [Environment]::SetEnvironmentVariable($Name, $Value)
        Write-Information "Set $Name=$Value" -InformationAction Continue
    }
}

function Get-AzurePrincipal {
    $accessToken = & az account get-access-token --resource https://management.azure.com/ --query accessToken --output tsv
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($accessToken)) {
        throw 'Unable to obtain an Azure management token. Run az login and azd auth login.'
    }
    $payload = $accessToken.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }
    $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
    if (-not $claims.oid) {
        throw 'The Azure token has no oid claim.'
    }
    return [pscustomobject]@{
        Id   = $claims.oid
        Type = if ($claims.idtyp -eq 'app') { 'ServicePrincipal' } else { 'User' }
    }
}

if (-not (Get-Command azd -ErrorAction SilentlyContinue)) {
    throw 'Azure Developer CLI (azd) is required.'
}
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI is required to resolve the deployment principal.'
}

$environmentName = Get-GsaEnvironmentValue -Name 'AZURE_ENV_NAME' -Required
Initialize-AzdEnvironmentValue -Name 'AZURE_LOCATION' -Value 'eastus'
Initialize-AzdEnvironmentValue -Name 'AZURE_RESOURCE_GROUP' -Value "rg-$environmentName-gsa"
Initialize-AzdEnvironmentValue -Name 'GSA_ORGANIZATION_NAME' -Value $environmentName

if ([string]::IsNullOrWhiteSpace($env:AZURE_PRINCIPAL_ID)) {
    $principal = Get-AzurePrincipal
    Initialize-AzdEnvironmentValue -Name 'AZURE_PRINCIPAL_ID' -Value $principal.Id
    Initialize-AzdEnvironmentValue -Name 'AZURE_PRINCIPAL_TYPE' -Value $principal.Type
}

$previewFeatures = @(
    Get-GsaBoolean $env:GSA_ENABLE_TENANT_ONBOARDING
    -not [string]::IsNullOrWhiteSpace($env:GSA_M365_PROFILE_STATE)
    -not [string]::IsNullOrWhiteSpace($env:GSA_PRIVATE_PROFILE_STATE)
    -not [string]::IsNullOrWhiteSpace($env:GSA_INTERNET_PROFILE_STATE)
    Get-GsaBoolean $env:GSA_ENABLE_QUICK_ACCESS
    Get-GsaBoolean $env:GSA_ENABLE_PRIVATE_ACCESS_APP
    Get-GsaBoolean $env:GSA_ENABLE_TLS_INSPECTION
    Get-GsaBoolean $env:GSA_ENABLE_INTERNET_BASELINE
)
if ($previewFeatures -contains $true) {
    Assert-GsaPreviewGate -Feature 'Configured Microsoft Graph operations' -Enabled $true
}

foreach ($name in 'GSA_M365_PROFILE_STATE', 'GSA_PRIVATE_PROFILE_STATE', 'GSA_INTERNET_PROFILE_STATE') {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ($value -and $value.ToLowerInvariant() -notin 'enabled', 'disabled', 'unchanged') {
        throw "$name must be Enabled, Disabled, or Unchanged."
    }
}

$privateEndpoint = Get-GsaBoolean $env:GSA_ENABLE_PRIVATE_ENDPOINT
if ($privateEndpoint) {
    Get-GsaEnvironmentValue -Name 'GSA_PRIVATE_ENDPOINT_SUBNET_ID' -Required | Out-Null
    Get-GsaEnvironmentValue -Name 'GSA_PRIVATE_DNS_ZONE_ID' -Required | Out-Null
    if (-not (Get-GsaBoolean $env:GSA_ACKNOWLEDGE_PRIVATE_ENDPOINT_RUNNER_ACCESS)) {
        throw 'Private endpoint mode requires GSA_ACKNOWLEDGE_PRIVATE_ENDPOINT_RUNNER_ACCESS=true to confirm the postprovision runner has private DNS and Key Vault connectivity.'
    }
}

if (Get-GsaBoolean $env:GSA_ENABLE_DIAGNOSTICS) {
    Get-GsaEnvironmentValue -Name 'GSA_LOG_ANALYTICS_WORKSPACE_ID' -Required | Out-Null
}

$assignmentMode = Get-GsaEnvironmentValue -Name 'GSA_INTUNE_ASSIGNMENT_MODE' -Default 'None'
if ($assignmentMode -notin 'None', 'PilotGroup', 'AllDevices') {
    throw 'GSA_INTUNE_ASSIGNMENT_MODE must be None, PilotGroup, or AllDevices.'
}
if ($assignmentMode -eq 'PilotGroup') {
    Get-GsaEnvironmentValue -Name 'GSA_PILOT_GROUP_ID' -Required | Out-Null
}
if (
    $assignmentMode -eq 'AllDevices' -or
    (Get-GsaBoolean $env:GSA_ENABLE_INTERNET_BASELINE) -or
    (Get-GsaBoolean $env:GSA_ALLOW_UNDOCUMENTED_TENANT_ONBOARDING)
) {
    if (-not (Get-GsaBoolean $env:GSA_ACKNOWLEDGE_LAB_MODE)) {
        throw 'Broad or tenant-wide preview operations require GSA_ACKNOWLEDGE_LAB_MODE=true.'
    }
}

Write-Information 'GSA pre-provision validation completed.' -InformationAction Continue
