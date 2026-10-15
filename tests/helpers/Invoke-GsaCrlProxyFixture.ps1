#Requires -Version 7.6
param(
    [Parameter(Mandatory)][string] $Root,
    [Parameter(Mandatory)][uri] $OriginUri,
    [Parameter(Mandatory)][uri] $ProxyUri
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $Root 'scripts/modules/Gsa.Readiness.psm1') -Force
$proxy = [Net.WebProxy]::new($ProxyUri, $false)
$proxy.Credentials = [Net.NetworkCredential]::new('proxy-user', 'proxy-secret')
if ($proxy.IsBypassed($OriginUri) -or $proxy.GetProxy($OriginUri).Port -ne $ProxyUri.Port) {
    throw 'The fixture proxy does not intercept the origin.'
}
# Isolate the process-wide proxy from unrelated background work in the test host.
[Net.Http.HttpClient]::DefaultProxy = $proxy
Get-GsaBoundedCrlEvidence -Uri $OriginUri.AbsoluteUri | ConvertTo-Json -Compress
