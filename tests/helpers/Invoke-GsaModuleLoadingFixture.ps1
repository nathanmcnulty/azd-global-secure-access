#Requires -Version 7.6
param(
    [Parameter(Mandatory)][string]$Root,
    [ValidateSet('PostProvision', 'PostProvisionState', 'ModuleGraph')][string]$Mode
)
$ErrorActionPreference = 'Stop'
foreach ($variable in @(Get-ChildItem Env:GSA_*)) {
    Remove-Item -LiteralPath "Env:$($variable.Name)"
}
foreach ($line in Get-Content (Join-Path $Root 'samples/azd-safe-poc.env')) {
    if ($line -match '^([A-Z][A-Z0-9_]+)="([^"]*)"$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2])
    }
}
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
$env:AZURE_ENV_NAME = 'fixture'
$env:AZURE_RESOURCE_GROUP = 'rg-fixture'
$env:AZURE_TENANT_ID = '11111111-1111-1111-1111-111111111111'
$env:AZURE_SUBSCRIPTION_ID = '22222222-2222-2222-2222-222222222222'
function az { throw 'Unexpected Azure call in local module-loading fixture.' }
function azd { throw 'Unexpected azd call in local module-loading fixture.' }
function Connect-MgGraph { throw 'Unexpected Graph authentication in local module-loading fixture.' }
try {
    Push-Location $tempRoot
    if ($Mode -eq 'PostProvisionState') {
        Copy-Item (Join-Path $Root 'scripts') (Join-Path $tempRoot 'scripts') -Recurse
        $env:GSA_KEY_VAULT_ID = '/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-fixture/providers/Microsoft.KeyVault/vaults/fixture'
        $env:GSA_KEY_VAULT_NAME = 'fixture'
        $env:GSA_KEY_VAULT_URI = 'https://fixture.vault.azure.net/'
        $env:GSA_CRL_STORAGE_ACCOUNT_ID = '/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-fixture/providers/Microsoft.Storage/storageAccounts/fixture'
        $env:GSA_CRL_STORAGE_ACCOUNT_NAME = 'fixture'
        $env:GSA_CRL_WEB_ENDPOINT = 'https://fixture.web.core.windows.net/'
        & (Join-Path $tempRoot 'scripts/Invoke-PostProvision.ps1') | Out-Null
        $manifest = Get-Content -Raw (Join-Path $tempRoot '.azure/fixture/gsa-state.json') | ConvertFrom-Json
        if (@($manifest.resources).Count -ne 2 -or @($manifest.resources | Where-Object kind -like 'Microsoft.Graph/*').Count -or (Test-Path (Join-Path $tempRoot '.azure/fixture/gsa-state.pending.json'))) {
            throw 'Safe foundation state did not commit exactly two Azure resources.'
        }
        'Foundation state committed without cloud calls.'
    } elseif ($Mode -eq 'PostProvision') {
        & (Join-Path $Root 'scripts/Invoke-PostProvision.ps1') -WhatIf
    } else {
        foreach ($name in @('Common', 'Graph', 'State', 'Certificate', 'Intune', 'Readiness', 'RemoteNetwork', 'Observability', 'Cleanup')) {
            Import-Module (Join-Path $Root "scripts/modules/Gsa.$name.psm1") -Force
        }
        foreach ($name in @('Get-GsaBoolean', 'Get-GsaTenantStatus', 'Get-GsaStatePath', 'Assert-GsaRootCertificate', 'Set-GsaIntuneTrustedRoot', 'ConvertTo-GsaReadinessCheck', 'Get-GsaRemoteNetworkPlan', 'Get-GsaObservabilityPlan', 'Get-GsaCleanupPlan')) {
            Get-Command $name -ErrorAction Stop | Out-Null
        }
        'Module exports remain available.'
    }
} finally {
    Pop-Location
    $resolvedTempRoot = (Resolve-Path -LiteralPath $tempRoot).Path
    if ($resolvedTempRoot -cne [IO.Path]::GetFullPath($tempRoot) -or
        [IO.Path]::GetDirectoryName($resolvedTempRoot).TrimEnd('\', '/') -ine [IO.Path]::GetTempPath().TrimEnd('\', '/')) {
        throw 'Fixture cleanup target is outside its exact temporary directory.'
    }
    Remove-Item -LiteralPath $resolvedTempRoot -Recurse -Force
}
