#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modulePath 'Gsa.Common.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.Graph.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.State.psm1') -Force

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
$azureCloud = Get-GsaEnvironmentValue -Name 'AZURE_CLOUD_NAME' -Default 'AzureCloud'
$graphEnvironment = Get-GsaEnvironmentValue -Name 'GSA_GRAPH_ENVIRONMENT' -Default 'Global'
$env:GSA_GRAPH_ENVIRONMENT = $graphEnvironment
$capability = Get-GsaCloudCapability -AzureCloud $azureCloud -GraphEnvironment $graphEnvironment
$desiredState = [ordered]@{
    tenantOnboarding = $enableOnboarding
    forwardingProfiles = $profileStates
    quickAccess = [ordered]@{
        enabled       = $enableQuickAccess
        name          = Get-GsaEnvironmentValue -Name 'GSA_QUICK_ACCESS_NAME' -Default 'GSA Quick Access'
        destinations  = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_QUICK_ACCESS_DESTINATIONS') -Separator ';'
        ports         = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_QUICK_ACCESS_PORTS' -Default '443')
        protocol      = Get-GsaEnvironmentValue -Name 'GSA_QUICK_ACCESS_PROTOCOL' -Default 'tcp'
        connectorGroupId = Get-GsaEnvironmentValue -Name 'GSA_CONNECTOR_GROUP_ID'
        pilotGroupId  = Get-GsaEnvironmentValue -Name 'GSA_PILOT_GROUP_ID'
    }
    privateAccess = [ordered]@{
        enabled       = $enablePrivateAccess
        name          = Get-GsaEnvironmentValue -Name 'GSA_PRIVATE_ACCESS_NAME' -Default 'GSA Private Access'
        destinations  = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_PRIVATE_ACCESS_DESTINATIONS') -Separator ';'
        ports         = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_PRIVATE_ACCESS_PORTS' -Default '443')
        protocol      = Get-GsaEnvironmentValue -Name 'GSA_PRIVATE_ACCESS_PROTOCOL' -Default 'tcp'
        connectorGroupId = Get-GsaEnvironmentValue -Name 'GSA_CONNECTOR_GROUP_ID'
        pilotGroupId  = Get-GsaEnvironmentValue -Name 'GSA_PILOT_GROUP_ID'
    }
    tlsInspection = [ordered]@{
        enabled             = $enableTls
        rootCertificateName = Get-GsaEnvironmentValue -Name 'GSA_ROOT_CERTIFICATE_NAME' -Default 'gsa-tls-root-ca'
        rootCommonName      = Get-GsaEnvironmentValue -Name 'GSA_ROOT_CERTIFICATE_CN' -Default 'Global Secure Access TLS Root CA'
        tlsCommonName       = Get-GsaEnvironmentValue -Name 'GSA_TLS_CERTIFICATE_CN' -Default 'Global Secure Access Inspection CA'
        crlHostname         = Get-GsaEnvironmentValue -Name 'GSA_CRL_CUSTOM_HOSTNAME'
        intunePlatforms     = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_INTUNE_PLATFORMS' -Default 'Windows,macOS,iOS/iPadOS,AndroidEnterpriseDeviceOwner,AndroidEnterpriseWorkProfile,AndroidAOSP')
        intuneAssignment    = Get-GsaEnvironmentValue -Name 'GSA_INTUNE_ASSIGNMENT_MODE' -Default 'None'
    }
    internetBaseline = [ordered]@{
        enabled              = $enableBaseline
        policyName           = Get-GsaEnvironmentValue -Name 'GSA_BASELINE_POLICY_NAME' -Default 'GSA POC Baseline Web Filtering'
        blockedCategories    = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_BASELINE_BLOCKED_CATEGORIES' -Default 'SocialNetworking')
        securityProfileName  = Get-GsaEnvironmentValue -Name 'GSA_BASELINE_SECURITY_PROFILE_NAME' -Default 'GSA POC Baseline Security Profile'
        securityProfilePriority = [int](Get-GsaEnvironmentValue -Name 'GSA_BASELINE_SECURITY_PROFILE_PRIORITY' -Default '100')
        policyLinkPriority   = [int](Get-GsaEnvironmentValue -Name 'GSA_BASELINE_POLICY_LINK_PRIORITY' -Default '100')
        conditionalAccessPolicyName = Get-GsaEnvironmentValue -Name 'GSA_BASELINE_CA_POLICY_NAME' -Default 'GSA POC Baseline Internet Access'
    }
}

if ($graphNeeded) {
    Assert-GsaCloudCapability -Capability $capability -Surface GraphCoreRead
    if ($profileStates.Count -gt 0) {
        Assert-GsaCloudCapability -Capability $capability -Surface ForwardingMutation
    }
    if ($enableOnboarding) {
        Assert-GsaCloudCapability -Capability $capability -Surface TenantOnboarding
    }
    if ($enableQuickAccess -or $enablePrivateAccess) {
        Assert-GsaCloudCapability -Capability $capability -Surface GraphMutation
    }
    if ($enableTls) {
        Assert-GsaCloudCapability -Capability $capability -Surface Tls
        Assert-GsaCloudCapability -Capability $capability -Surface AzureDataPlane
    }
    if ($enableBaseline) {
        Assert-GsaCloudCapability -Capability $capability -Surface Filtering
    }
    if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
        throw 'Install Microsoft.Graph.Authentication before running Graph automation.'
    }
    $scopes = [System.Collections.Generic.List[string]]::new()
    $scopes.Add('NetworkAccess.ReadWrite.All')
    $scopes.Add('NetworkAccessPolicy.Read.All')
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
    $graphContext = Connect-GsaGraph -Scopes @($scopes | Select-Object -Unique) -Environment $graphEnvironment

    $azureTenantId = Get-GsaEnvironmentValue -Name 'AZURE_TENANT_ID'
    if ($azureTenantId -and $graphContext.TenantId -ne $azureTenantId) {
        throw "Graph tenant '$($graphContext.TenantId)' does not match Azure tenant '$azureTenantId'."
    }
    $results.TenantStatus = Get-GsaTenantStatus
}

$environmentIdentity = [ordered]@{
    name              = Get-GsaEnvironmentValue -Name 'AZURE_ENV_NAME' -Required
    tenantId          = if ($graphNeeded) { $graphContext.TenantId } else { Get-GsaEnvironmentValue -Name 'AZURE_TENANT_ID' -Required }
    subscriptionId    = Get-GsaEnvironmentValue -Name 'AZURE_SUBSCRIPTION_ID' -Required
    resourceGroupName = Get-GsaEnvironmentValue -Name 'AZURE_RESOURCE_GROUP' -Required
    azureCloud        = $azureCloud
    graphEnvironment  = $graphEnvironment
}
$manifestPath = Get-GsaStatePath
$pendingPath = Get-GsaStatePath -Pending
$previousManifest = Read-GsaStateManifest -Path $manifestPath
if ($previousManifest) {
    $previousDesiredState = $previousManifest.desiredState.configuration
    if (-not $enableOnboarding -and $previousDesiredState.tenantOnboarding) {
        $desiredState.tenantOnboarding = $true
    }
    $cumulativeProfileStates = [ordered]@{}
    foreach ($property in @($previousDesiredState.forwardingProfiles.PSObject.Properties)) {
        $cumulativeProfileStates[$property.Name] = $property.Value
    }
    foreach ($entry in $profileStates.GetEnumerator()) {
        $cumulativeProfileStates[$entry.Key] = $entry.Value
    }
    $desiredState.forwardingProfiles = $cumulativeProfileStates
    if (-not $enableQuickAccess -and $previousDesiredState.quickAccess.enabled) {
        $desiredState.quickAccess = $previousDesiredState.quickAccess
    }
    if (-not $enablePrivateAccess -and $previousDesiredState.privateAccess.enabled) {
        $desiredState.privateAccess = $previousDesiredState.privateAccess
    }
    if (-not $enableTls -and $previousDesiredState.tlsInspection.enabled) {
        $desiredState.tlsInspection = $previousDesiredState.tlsInspection
    }
    if (-not $enableBaseline -and $previousDesiredState.internetBaseline.enabled) {
        $desiredState.internetBaseline = $previousDesiredState.internetBaseline
    }
}
$transaction = if (-not $WhatIfPreference) {
    Write-GsaPendingTransaction -Environment $environmentIdentity -DesiredState $desiredState -Path $pendingPath
} else {
    $null
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
    $destinations = $desiredState.quickAccess.destinations
    $ports = $desiredState.quickAccess.ports
    $results.QuickAccess = Set-GsaPrivateApplication `
        -ApplicationType quickaccessapp `
        -DisplayName $desiredState.quickAccess.name `
        -ConnectorGroupId ([guid]$connectorGroupText) `
        -Destinations $destinations `
        -Ports $ports `
        -Protocol $desiredState.quickAccess.protocol `
        -PilotGroupId $pilotGroup `
        -AllowAdditionalSegments:(Get-GsaBoolean $env:GSA_ALLOW_ADDITIONAL_PRIVATE_ACCESS_SEGMENTS) `
        -AllowAdditionalAssignments:(Get-GsaBoolean $env:GSA_ALLOW_ADDITIONAL_ASSIGNMENTS) `
        -WhatIf:$WhatIfPreference
}

if ($enablePrivateAccess) {
    $destinations = $desiredState.privateAccess.destinations
    $ports = $desiredState.privateAccess.ports
    $results.PrivateAccess = Set-GsaPrivateApplication `
        -ApplicationType nonwebapp `
        -DisplayName $desiredState.privateAccess.name `
        -ConnectorGroupId ([guid]$connectorGroupText) `
        -Destinations $destinations `
        -Ports $ports `
        -Protocol $desiredState.privateAccess.protocol `
        -PilotGroupId $pilotGroup `
        -AllowAdditionalSegments:(Get-GsaBoolean $env:GSA_ALLOW_ADDITIONAL_PRIVATE_ACCESS_SEGMENTS) `
        -AllowAdditionalAssignments:(Get-GsaBoolean $env:GSA_ALLOW_ADDITIONAL_ASSIGNMENTS) `
        -WhatIf:$WhatIfPreference
}

if ($enableBaseline) {
    $results.InternetBaseline = Set-GsaInternetBaseline `
        -Name $desiredState.internetBaseline.policyName `
        -BlockedCategories $desiredState.internetBaseline.blockedCategories `
        -SecurityProfileName $desiredState.internetBaseline.securityProfileName `
        -ConditionalAccessPolicyName $desiredState.internetBaseline.conditionalAccessPolicyName `
        -SecurityProfilePriority $desiredState.internetBaseline.securityProfilePriority `
        -PolicyLinkPriority $desiredState.internetBaseline.policyLinkPriority `
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

    $results.Intune = Set-GsaIntuneTrustedRoot `
        -Certificate $root.Certificate `
        -Platforms $desiredState.tlsInspection.intunePlatforms `
        -AssignmentMode $desiredState.tlsInspection.intuneAssignment `
        -PilotGroupId $pilotGroup `
        -AcknowledgeLabMode:(Get-GsaBoolean $env:GSA_ACKNOWLEDGE_LAB_MODE) `
        -AllowAdditionalAssignments:(Get-GsaBoolean $env:GSA_ALLOW_ADDITIONAL_ASSIGNMENTS) `
        -WhatIf:$WhatIfPreference
}

if (-not $WhatIfPreference) {
    $resources = [System.Collections.Generic.List[object]]::new()
    function Add-GsaStateResource {
        param(
            [Parameter(Mandatory)][string]$Key,
            [Parameter(Mandatory)][string]$Kind,
            [AllowNull()][string]$Id,
            [Parameter(Mandatory)][object]$NaturalId,
            [Parameter(Mandatory)][object]$Desired,
            [AllowNull()][object]$Observed,
            [AllowNull()][object]$PreviousState,
            [AllowNull()][string]$ReadUri,
            [bool]$Created,
            [ValidateSet('managed', 'reused')][string]$Ownership,
            [ValidateSet('created', 'reused', 'declared')][string]$Provenance,
            [ValidateSet('active', 'retired')][string]$LifecycleState
        )
        $parameters = @{
            Key = $Key
            Kind = $Kind
            Id = $Id
            NaturalId = $NaturalId
            DesiredState = $Desired
            ObservedState = $Observed
            PreviousMutableState = $PreviousState
            ReadUri = $ReadUri
            Created = $Created
            PreviousManifest = $previousManifest
        }
        if ($Ownership) { $parameters.Ownership = $Ownership }
        if ($Provenance) { $parameters.Provenance = $Provenance }
        if ($LifecycleState) { $parameters.LifecycleState = $LifecycleState }
        $resources.Add((ConvertTo-GsaStateResource @parameters))
    }

    $keyVaultId = Get-GsaEnvironmentValue -Name 'GSA_KEY_VAULT_ID'
    if ($keyVaultId) {
        Add-GsaStateResource -Key 'azure:keyVault' -Kind 'Microsoft.KeyVault/vaults' -Id $keyVaultId `
            -NaturalId @{ name = Get-GsaEnvironmentValue -Name 'GSA_KEY_VAULT_NAME' -Required } `
            -Desired @{ resourceGroupName = $environmentIdentity.resourceGroupName } `
            -Observed @{ uri = Get-GsaEnvironmentValue -Name 'GSA_KEY_VAULT_URI' -Required } `
            -Ownership managed -Provenance declared
    }
    $storageAccountId = Get-GsaEnvironmentValue -Name 'GSA_CRL_STORAGE_ACCOUNT_ID'
    if ($storageAccountId) {
        Add-GsaStateResource -Key 'azure:crlStorage' -Kind 'Microsoft.Storage/storageAccounts' -Id $storageAccountId `
            -NaturalId @{ name = Get-GsaEnvironmentValue -Name 'GSA_CRL_STORAGE_ACCOUNT_NAME' -Required } `
            -Desired @{ resourceGroupName = $environmentIdentity.resourceGroupName } `
            -Observed @{ webEndpoint = Get-GsaEnvironmentValue -Name 'GSA_CRL_WEB_ENDPOINT' -Required } `
            -Ownership managed -Provenance declared
    }

    if ($results.TenantStatus) {
        Add-GsaStateResource -Key 'networkAccess:tenantStatus' -Kind 'Microsoft.Graph/networkAccess/tenantStatus' `
            -Id $results.TenantStatus.id -NaturalId @{ tenantId = $environmentIdentity.tenantId } `
            -Desired @{ onboardingStatus = [string]$results.TenantStatus.onboardingStatus } `
            -Observed $results.TenantStatus -ReadUri '/beta/networkAccess/tenantStatus' -Created:$false
    }
    foreach ($forwardingProfile in @($results.ForwardingProfiles)) {
        Add-GsaStateResource -Key "forwardingProfile:$($forwardingProfile.TrafficType)" -Kind 'Microsoft.Graph/networkAccess/forwardingProfile' `
            -Id $forwardingProfile.Id -NaturalId @{ trafficForwardingType = $forwardingProfile.TrafficType } `
            -Desired @{ state = $forwardingProfile.State; trafficForwardingType = $forwardingProfile.TrafficType } `
            -Observed @{ state = $forwardingProfile.State; trafficForwardingType = $forwardingProfile.TrafficType } `
            -PreviousState @{ state = $forwardingProfile.PreviousState } `
            -ReadUri "/beta/networkAccess/forwardingProfiles/$($forwardingProfile.Id)" -Created:$false
    }
    foreach ($entry in @(
        @{ Name = 'QuickAccess'; Type = 'quickaccessapp'; Desired = $desiredState.quickAccess },
        @{ Name = 'PrivateAccess'; Type = 'nonwebapp'; Desired = $desiredState.privateAccess }
    )) {
        $application = $results[$entry.Name]
        if ($application) {
            $applicationDesiredState = [ordered]@{
                appId       = $application.AppId
                displayName = $application.DisplayName
                onPremisesPublishing = [ordered]@{
                    applicationType           = $entry.Type
                    isAccessibleViaZTNAClient = $true
                }
            }
            Add-GsaStateResource -Key "privateApplication:$($entry.Type):$($application.AppId)" -Kind 'Microsoft.Graph/applications' `
                -Id $application.ApplicationId -NaturalId @{ appId = $application.AppId; applicationType = $entry.Type } `
                -Desired $applicationDesiredState -Observed $application `
                -ReadUri "/beta/applications/$($application.ApplicationId)?`$select=id,appId,displayName,onPremisesPublishing" `
                -Created:$application.Created
            Add-GsaStateResource -Key "servicePrincipal:$($application.AppId)" -Kind 'Microsoft.Graph/servicePrincipals' `
                -Id $application.ServicePrincipalId -NaturalId @{ appId = $application.AppId } `
                -Desired @{ appId = $application.AppId } -Observed @{ appId = $application.AppId } `
                -ReadUri "/v1.0/servicePrincipals/$($application.ServicePrincipalId)?`$select=id,appId" `
                -Created:$application.Created
        }
    }
    if ($connectorGroupText) {
        Add-GsaStateResource -Key "connectorGroup:$connectorGroupText" -Kind 'Microsoft.Graph/onPremisesPublishing/connectorGroup' `
            -Id $connectorGroupText -NaturalId @{ id = $connectorGroupText } -Desired @{ id = $connectorGroupText } `
            -Observed @{ id = $connectorGroupText } `
            -ReadUri "/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$connectorGroupText" -Created:$false
    }
    if ($results.InternetBaseline) {
        $baseline = $results.InternetBaseline
        Add-GsaStateResource -Key "filteringPolicy:$($baseline.FilteringPolicyName)" -Kind 'Microsoft.Graph/networkAccess/filteringPolicy' `
            -Id $baseline.FilteringPolicyId -NaturalId @{ name = $baseline.FilteringPolicyName } `
            -Desired @{ name = $baseline.FilteringPolicyName; action = 'block'; policyRules = @(@{ ruleType = 'webCategory'; destinations = @($baseline.BlockedCategories | ForEach-Object { @{ name = $_ } }) }) } `
            -Observed @{ name = $baseline.FilteringPolicyName; action = 'block'; policyRules = @(@{ ruleType = 'webCategory'; destinations = @($baseline.BlockedCategories | ForEach-Object { @{ name = $_ } }) }) } `
            -ReadUri "/beta/networkAccess/filteringPolicies/$($baseline.FilteringPolicyId)?`$expand=policyRules" -Created:$baseline.FilteringPolicyCreated
        Add-GsaStateResource -Key "filteringProfile:$($baseline.SecurityProfileName)" -Kind 'Microsoft.Graph/networkAccess/filteringProfile' `
            -Id $baseline.SecurityProfileId -NaturalId @{ name = $baseline.SecurityProfileName } `
            -Desired @{ name = $baseline.SecurityProfileName; state = 'enabled'; priority = $desiredState.internetBaseline.securityProfilePriority } `
            -Observed @{ name = $baseline.SecurityProfileName; state = 'enabled'; priority = $desiredState.internetBaseline.securityProfilePriority } `
            -ReadUri "/beta/networkAccess/filteringProfiles/$($baseline.SecurityProfileId)" -Created:$baseline.SecurityProfileCreated
        Add-GsaStateResource -Key "conditionalAccessPolicy:$($baseline.ConditionalAccessPolicyName)" -Kind 'Microsoft.Graph/identity/conditionalAccess/policy' `
            -Id $baseline.ConditionalAccessPolicyId -NaturalId @{ displayName = $baseline.ConditionalAccessPolicyName } `
            -Desired @{ displayName = $baseline.ConditionalAccessPolicyName; state = 'disabled' } `
            -Observed @{ displayName = $baseline.ConditionalAccessPolicyName; state = $baseline.ConditionalAccessState } `
            -ReadUri "/beta/identity/conditionalAccess/policies/$($baseline.ConditionalAccessPolicyId)" -Created:$baseline.ConditionalAccessPolicyCreated
    }
    if ($enableTls) {
        Add-GsaStateResource -Key "keyVaultCertificate:$($root.Thumbprint)" -Kind 'Microsoft.KeyVault/certificates' `
            -Id $root.KeyId -NaturalId @{ vaultName = Get-GsaEnvironmentValue -Name 'GSA_KEY_VAULT_NAME' -Required; certificateName = $desiredState.tlsInspection.rootCertificateName } `
            -Desired @{ subject = $root.Certificate.Subject; thumbprint = $root.Thumbprint } `
            -Observed @{ subject = $root.Certificate.Subject; thumbprint = $root.Thumbprint; notAfter = $root.Certificate.NotAfter.ToUniversalTime().ToString('O') } `
            -Created:$root.Created
        Add-GsaStateResource -Key "crl:$($results.Crl.Url)" -Kind 'Microsoft.Storage/crl' `
            -Id $results.Crl.Url -NaturalId @{ url = $results.Crl.Url } `
            -Desired @{ url = $results.Crl.Url } -Observed $results.Crl -Created:$true
        Add-GsaStateResource -Key "tlsCertificate:$($results.TlsCertificate.Id)" -Kind 'Microsoft.Graph/networkAccess/externalCertificateAuthorityCertificate' `
            -Id $results.TlsCertificate.Id -NaturalId @{ name = $results.TlsCertificate.Name } `
            -Desired @{ name = $results.TlsCertificate.Name; status = $results.TlsCertificate.Status } `
            -Observed $results.TlsCertificate `
            -ReadUri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$($results.TlsCertificate.Id)" `
            -Created:$results.TlsCertificate.Created
        foreach ($intuneProfile in @($results.Intune | Where-Object Id)) {
            Add-GsaStateResource -Key "intuneTrustedRoot:$($intuneProfile.Platform)" -Kind 'Microsoft.Graph/deviceManagement/deviceConfiguration' `
                -Id $intuneProfile.Id -NaturalId @{ platform = $intuneProfile.Platform; id = $intuneProfile.Id } `
                -Desired @{ displayName = $intuneProfile.Name } -Observed $intuneProfile `
                -ReadUri "/beta/deviceManagement/deviceConfigurations/$($intuneProfile.Id)" -Created:$intuneProfile.Created
        }
    }

    $mergedResources = Merge-GsaStateResourceSet -CurrentResources $resources.ToArray() -PreviousManifest $previousManifest
    $manifest = ConvertTo-GsaStateManifest -Environment $environmentIdentity -DesiredState $desiredState `
        -Resources $mergedResources -OperationId $transaction.operationId
    Complete-GsaStateTransaction -Transaction $transaction -Manifest $manifest -ManifestPath $manifestPath -PendingPath $pendingPath
    $results.StateManifest = [ordered]@{
        path              = $manifestPath
        schemaVersion     = $manifest.schemaVersion
        desiredFingerprint = $manifest.desiredState.fingerprint
        resourceCount     = $manifest.resources.Count
    }
}

$results | ConvertTo-Json -Depth 20
