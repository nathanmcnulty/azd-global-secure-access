#Requires -Version 7.6
param(
    [Parameter(Mandatory)][string]$Root,
    [ValidateSet('PostProvision', 'ModuleGraph')][string]$Mode
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
    if ($Mode -eq 'PostProvision') {
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
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}
