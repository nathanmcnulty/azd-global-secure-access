#Requires -Version 7.6
param([ValidateSet('matched','mismatch','failed','wrongType','absent','emptyBaseline','unrelatedBaseline','noManifest','emptyManifest')][string]$Case, [string]$Root)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $Root 'scripts/modules/Gsa.Readiness.psm1') -Force
function Import-Module { param($Name, [switch]$Force) }
function Get-Module { param([switch]$ListAvailable, $Name) [pscustomobject]@{ Name='FixtureOnly' } }
function Assert-GsaPreviewGate { param($Feature, $Enabled) }
function Get-GsaEnvironmentValue { param($Name, $Default) $Default }
function Get-GsaCloudCapability { param($AzureCloud, $GraphEnvironment) [pscustomobject]@{ GraphCoreRead=$false; Evidence='Fixture unsupported cloud'; ExpectedGraphEnvironments=@() } }
function Get-GsaStatePath { param([switch]$Pending) Join-Path $PSScriptRoot 'nonexistent-fixture-state.json' }
function Read-GsaStateManifest {
    param($Path)
    if ($Case -eq 'noManifest') { return $null }
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]](1,2,3,4)))
    if ($Case -eq 'mismatch') { $digest = 'A' * 64 }
    [pscustomobject]@{
        schemaVersion='1.0.0'; desiredState=[pscustomobject]@{ fingerprint='fixture' }
        resources=@($(if ($Case -notin @('emptyBaseline','emptyManifest')) {
            [pscustomobject]@{ kind=$(if ($Case -eq 'unrelatedBaseline') { 'UnrelatedFixture' } else { 'Microsoft.Graph/networkAccess/filteringPolicy' }); key='fixtureBaseline' }
        }); $(if ($Case -notin @('absent','emptyManifest')) {
            [pscustomobject]@{ kind='Microsoft.Storage/crl'; id='http://CANARY_URL.invalid/?sig=CANARY_SIG'; key='fixtureCrl'; ownership='managed'; observedState=[pscustomobject]@{ NextUpdate='2099-11-11T00:00:00Z'; Sha256=$digest } }
        }))
    }
}
$global:gsaCrlFixtureReads = 0
function Invoke-WebRequest {
    param($Uri, $TimeoutSec)
    $global:gsaCrlFixtureReads++
    if ($Uri -cne 'http://CANARY_URL.invalid/?sig=CANARY_SIG' -or $TimeoutSec -ne 15) { throw 'FORBIDDEN_DISPATCH' }
    if ($Case -eq 'failed') { throw [System.Exception]::new('CANARY_PROVIDER CANARY_TOKEN', [System.Exception]::new('CANARY_INNER')) }
    [pscustomobject]@{ StatusCode=200; Content=[byte[]](1,2,3,4); Headers=@{ 'Content-Type'=$(if ($Case -eq 'wrongType') { 'text/plain' } else { 'application/pkix-crl' }) } }
}
function Connect-GsaGraph { throw 'FORBIDDEN_DISPATCH' }
function Invoke-MgGraphRequest { throw 'FORBIDDEN_DISPATCH' }
function Connect-AzAccount { throw 'FORBIDDEN_DISPATCH' }
function Invoke-CrlRenewal { throw 'FORBIDDEN_DISPATCH' }
function Publish-GsaCrl { throw 'FORBIDDEN_DISPATCH' }
function Invoke-GsaKeyVault { throw 'FORBIDDEN_DISPATCH' }
function Write-GsaAtomicJson { throw 'FORBIDDEN_DISPATCH' }
& (Join-Path $Root 'scripts/Test-GsaReadiness.ps1') -JsonOnly

$entryExit = $LASTEXITCODE
$expectedReads = if ($Case -in @('absent','noManifest','emptyManifest')) { 0 } else { 1 }
if ($global:gsaCrlFixtureReads -ne $expectedReads) { throw 'Unexpected fixture CRL read count' }
exit $entryExit
