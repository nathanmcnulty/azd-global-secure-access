#Requires -Version 7.0
#Requires -Modules Az.Accounts

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$KeyVaultName,
    [Parameter(Mandatory)][string]$StorageAccountName,
    [Parameter(Mandatory)][string]$WebEndpoint,
    [string]$RootCertificateName = 'gsa-tls-root-ca',
    [string]$CustomHostname
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'modules\Gsa.Certificate.psm1') -Force

if (-not (Get-AzContext)) {
    throw 'Run Connect-AzAccount before renewing the CRL.'
}

$root = Get-GsaKeyVaultCertificate -VaultName $KeyVaultName -CertificateName $RootCertificateName
Assert-GsaRootCertificate -CertificateInfo $root
Publish-GsaCrl `
    -StorageAccountName $StorageAccountName `
    -WebEndpoint $WebEndpoint `
    -Issuer $root `
    -CustomHostname $CustomHostname `
    -WhatIf:$WhatIfPreference
