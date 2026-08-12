#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modulePath 'Gsa.Common.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.Graph.psm1') -Force

$profileStates = [ordered]@{}
$profileEnvironmentMap = @{
    m365     = 'GSA_M365_PROFILE_STATE'
    private  = 'GSA_PRIVATE_PROFILE_STATE'
    internet = 'GSA_INTERNET_PROFILE_STATE'
}
foreach ($entry in $profileEnvironmentMap.GetEnumerator()) {
    $state = [Environment]::GetEnvironmentVariable($entry.Value)
    if ($state -and $state.ToLowerInvariant() -ne 'unchanged') {
        $profileStates[$entry.Key] = $state.ToLowerInvariant() -eq 'enabled'
    }
}

$enableOnboarding = Get-GsaBoolean $env:GSA_ENABLE_TENANT_ONBOARDING
$enableQuickAccess = Get-GsaBoolean $env:GSA_ENABLE_QUICK_ACCESS
$enablePrivateAccess = Get-GsaBoolean $env:GSA_ENABLE_PRIVATE_ACCESS_APP
$enableTls = Get-GsaBoolean $env:GSA_ENABLE_TLS_INSPECTION
$enableBaseline = Get-GsaBoolean $env:GSA_ENABLE_INTERNET_BASELINE
$graphNeeded = $enableOnboarding -or $profileStates.Count -gt 0 -or $enableQuickAccess -or $enablePrivateAccess -or $enableTls -or $enableBaseline
$results = [ordered]@{}

if ($graphNeeded) {
    if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
        throw 'Install Microsoft.Graph.Authentication before running Graph automation.'
    }
    $scopes = [System.Collections.Generic.List[string]]::new()
    $scopes.Add('NetworkAccess.ReadWrite.All')
    if ($enableQuickAccess -or $enablePrivateAccess) {
        $scopes.Add('Directory.ReadWrite.All')
        $scopes.Add('AppRoleAssignment.ReadWrite.All')
    }
    if ($enableTls) {
        $scopes.Add('DeviceManagementConfiguration.ReadWrite.All')
    }
    if ($enableBaseline) {
        $scopes.Add('Policy.ReadWrite.ConditionalAccess')
    }
    $graphContext = Connect-GsaGraph -Scopes @($scopes | Select-Object -Unique)

    $azureTenantId = Get-GsaEnvironmentValue -Name 'AZURE_TENANT_ID'
    if ($azureTenantId -and $graphContext.TenantId -ne $azureTenantId) {
        throw "Graph tenant '$($graphContext.TenantId)' does not match Azure tenant '$azureTenantId'."
    }
    $results.TenantStatus = Get-GsaTenantStatus
}

if ($enableOnboarding) {
    $results.TenantStatus = Enable-GsaTenantOnboarding `
        -AllowUndocumentedPermission:(Get-GsaBoolean $env:GSA_ALLOW_UNDOCUMENTED_TENANT_ONBOARDING) `
        -WhatIf:$WhatIfPreference
}

if ($profileStates.Count -gt 0) {
    $results.ForwardingProfiles = Set-GsaForwardingProfile -DesiredState $profileStates -WhatIf:$WhatIfPreference
}

$connectorGroupText = Get-GsaEnvironmentValue -Name 'GSA_CONNECTOR_GROUP_ID'
$pilotGroupText = Get-GsaEnvironmentValue -Name 'GSA_PILOT_GROUP_ID'
$pilotGroup = if ($pilotGroupText) { [guid]$pilotGroupText } else { [guid]::Empty }

if ($enableQuickAccess -or $enablePrivateAccess) {
    if (-not $connectorGroupText) {
        throw 'Quick Access and Private Access require an existing GSA_CONNECTOR_GROUP_ID.'
    }
}

if ($enableQuickAccess) {
    $destinations = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_QUICK_ACCESS_DESTINATIONS' -Required) -Separator ';'
    $ports = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_QUICK_ACCESS_PORTS' -Default '443')
    $results.QuickAccess = Set-GsaPrivateApplication `
        -ApplicationType quickaccessapp `
        -DisplayName (Get-GsaEnvironmentValue -Name 'GSA_QUICK_ACCESS_NAME' -Default 'GSA Quick Access') `
        -ConnectorGroupId ([guid]$connectorGroupText) `
        -Destinations $destinations `
        -Ports $ports `
        -Protocol (Get-GsaEnvironmentValue -Name 'GSA_QUICK_ACCESS_PROTOCOL' -Default 'tcp') `
        -PilotGroupId $pilotGroup `
        -AllowAdditionalSegments:(Get-GsaBoolean $env:GSA_ALLOW_ADDITIONAL_PRIVATE_ACCESS_SEGMENTS) `
        -AllowAdditionalAssignments:(Get-GsaBoolean $env:GSA_ALLOW_ADDITIONAL_ASSIGNMENTS) `
        -WhatIf:$WhatIfPreference
}

if ($enablePrivateAccess) {
    $destinations = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_PRIVATE_ACCESS_DESTINATIONS' -Required) -Separator ';'
    $ports = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_PRIVATE_ACCESS_PORTS' -Default '443')
    $results.PrivateAccess = Set-GsaPrivateApplication `
        -ApplicationType nonwebapp `
        -DisplayName (Get-GsaEnvironmentValue -Name 'GSA_PRIVATE_ACCESS_NAME' -Default 'GSA Private Access') `
        -ConnectorGroupId ([guid]$connectorGroupText) `
        -Destinations $destinations `
        -Ports $ports `
        -Protocol (Get-GsaEnvironmentValue -Name 'GSA_PRIVATE_ACCESS_PROTOCOL' -Default 'tcp') `
        -PilotGroupId $pilotGroup `
        -AllowAdditionalSegments:(Get-GsaBoolean $env:GSA_ALLOW_ADDITIONAL_PRIVATE_ACCESS_SEGMENTS) `
        -AllowAdditionalAssignments:(Get-GsaBoolean $env:GSA_ALLOW_ADDITIONAL_ASSIGNMENTS) `
        -WhatIf:$WhatIfPreference
}

if ($enableBaseline) {
    $categories = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_BASELINE_BLOCKED_CATEGORIES' -Default 'SocialNetworking')
    $results.InternetBaseline = Set-GsaInternetBaseline `
        -Name (Get-GsaEnvironmentValue -Name 'GSA_BASELINE_POLICY_NAME' -Default 'GSA POC Baseline Web Filtering') `
        -BlockedCategories $categories `
        -SecurityProfileName (Get-GsaEnvironmentValue -Name 'GSA_BASELINE_SECURITY_PROFILE_NAME' -Default 'GSA POC Baseline Security Profile') `
        -ConditionalAccessPolicyName (Get-GsaEnvironmentValue -Name 'GSA_BASELINE_CA_POLICY_NAME' -Default 'GSA POC Baseline Internet Access') `
        -SecurityProfilePriority ([int](Get-GsaEnvironmentValue -Name 'GSA_BASELINE_SECURITY_PROFILE_PRIORITY' -Default '100')) `
        -PolicyLinkPriority ([int](Get-GsaEnvironmentValue -Name 'GSA_BASELINE_POLICY_LINK_PRIORITY' -Default '100')) `
        -WhatIf:$WhatIfPreference
}

if ($enableTls) {
    if (-not (Get-Module -ListAvailable Az.Accounts)) {
        throw 'Install Az.Accounts before running TLS automation.'
    }
    Import-Module Az.Accounts
    $azContext = Get-AzContext
    if (-not $azContext) {
        throw 'TLS automation requires an Az PowerShell context. Run Connect-AzAccount in the deployment tenant.'
    }
    if ($graphContext.TenantId -ne $azContext.Tenant.Id) {
        throw "Graph tenant '$($graphContext.TenantId)' does not match Az tenant '$($azContext.Tenant.Id)'."
    }

    Import-Module (Join-Path $modulePath 'Gsa.Certificate.psm1') -Force
    Import-Module (Join-Path $modulePath 'Gsa.Intune.psm1') -Force
    $organization = Get-GsaEnvironmentValue -Name 'GSA_ORGANIZATION_NAME' -Required
    $root = Get-OrCreateGsaRootCertificate `
        -VaultName (Get-GsaEnvironmentValue -Name 'GSA_KEY_VAULT_NAME' -Required) `
        -CertificateName (Get-GsaEnvironmentValue -Name 'GSA_ROOT_CERTIFICATE_NAME' -Default 'gsa-tls-root-ca') `
        -CommonName (Get-GsaEnvironmentValue -Name 'GSA_ROOT_CERTIFICATE_CN' -Default 'Global Secure Access TLS Root CA') `
        -OrganizationName $organization `
        -WhatIf:$WhatIfPreference

    $crl = Publish-GsaCrl `
        -StorageAccountName (Get-GsaEnvironmentValue -Name 'GSA_CRL_STORAGE_ACCOUNT_NAME' -Required) `
        -WebEndpoint (Get-GsaEnvironmentValue -Name 'GSA_CRL_WEB_ENDPOINT' -Required) `
        -Issuer $root `
        -CustomHostname (Get-GsaEnvironmentValue -Name 'GSA_CRL_CUSTOM_HOSTNAME') `
        -EnsureStaticWebsite `
        -WhatIf:$WhatIfPreference

    $results.TlsCertificate = Set-GsaTlsCertificate `
        -RootCertificate $root `
        -CrlUrl $crl.Url `
        -CommonName (Get-GsaEnvironmentValue -Name 'GSA_TLS_CERTIFICATE_CN' -Default 'Global Secure Access Inspection CA') `
        -OrganizationName $organization `
        -Rotate:(Get-GsaBoolean $env:GSA_ROTATE_TLS_CERTIFICATE) `
        -AllowUndocumentedEnable:(Get-GsaBoolean $env:GSA_ALLOW_UNDOCUMENTED_CERTIFICATE_ENABLE) `
        -WhatIf:$WhatIfPreference
    $results.Crl = $crl

    $platforms = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_INTUNE_PLATFORMS' -Default 'Windows,macOS,iOS/iPadOS,AndroidEnterpriseDeviceOwner,AndroidEnterpriseWorkProfile,AndroidAOSP')
    $results.Intune = Set-GsaIntuneTrustedRoot `
        -Certificate $root.Certificate `
        -Platforms $platforms `
        -AssignmentMode (Get-GsaEnvironmentValue -Name 'GSA_INTUNE_ASSIGNMENT_MODE' -Default 'None') `
        -PilotGroupId $pilotGroup `
        -AcknowledgeLabMode:(Get-GsaBoolean $env:GSA_ACKNOWLEDGE_LAB_MODE) `
        -AllowAdditionalAssignments:(Get-GsaBoolean $env:GSA_ALLOW_ADDITIONAL_ASSIGNMENTS) `
        -WhatIf:$WhatIfPreference
}

$results | ConvertTo-Json -Depth 12
