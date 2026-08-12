Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonPath = Join-Path $PSScriptRoot 'Gsa.Common.psm1'
Import-Module $commonPath -Force

function Get-GsaTenantStatus {
    [CmdletBinding()]
    param()

    Assert-GsaPreviewGate -Feature 'Global Secure Access tenant state' -Enabled $true
    return Invoke-MgGraphRequest -Method GET -Uri '/beta/networkAccess/tenantStatus' -OutputType PSObject
}

function Enable-GsaTenantOnboarding {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$AllowUndocumentedPermission
    )

    Assert-GsaPreviewGate -Feature 'Global Secure Access tenant onboarding' -Enabled $true
    if (-not $AllowUndocumentedPermission) {
        throw 'The onboarding operation has no documented OAuth permission. Complete onboarding in the Entra portal or explicitly allow a tenant-validated invocation.'
    }

    $status = Get-GsaTenantStatus
    if ($status.onboardingStatus -eq 'onboarded') {
        return $status
    }
    if ($status.onboardingStatus -ne 'offboarded') {
        throw "Tenant onboarding is already in state '$($status.onboardingStatus)': $($status.onboardingErrorMessage)"
    }
    if ($PSCmdlet.ShouldProcess('Microsoft Entra tenant', 'Start Global Secure Access onboarding')) {
        Invoke-MgGraphRequest -Method POST -Uri '/beta/networkAccess/microsoft.graph.networkaccess.onboard' | Out-Null
    }
    return Get-GsaTenantStatus
}

function Set-GsaForwardingProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [hashtable]$DesiredState
    )

    Assert-GsaPreviewGate -Feature 'Global Secure Access forwarding profiles' -Enabled $true
    $profiles = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/forwardingProfiles')
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($trafficType in 'm365', 'private', 'internet') {
        if (-not $DesiredState.ContainsKey($trafficType)) {
            continue
        }
        $profileMatches = @($profiles | Where-Object { $_.trafficForwardingType -eq $trafficType })
        if ($profileMatches.Count -ne 1) {
            throw "Expected one '$trafficType' forwarding profile but found $($profileMatches.Count)."
        }

        $forwardingProfile = $profileMatches[0]
        $desired = if ([bool]$DesiredState[$trafficType]) { 'enabled' } else { 'disabled' }
        $changed = $false
        if ($forwardingProfile.state -ne $desired) {
            if ($PSCmdlet.ShouldProcess($forwardingProfile.name, "Set forwarding profile state to '$desired'")) {
                $body = @{ state = $desired } | ConvertTo-Json -Compress
                Invoke-MgGraphRequest -Method PATCH -Uri "/beta/networkAccess/forwardingProfiles/$($forwardingProfile.id)" -Body $body -ContentType 'application/json' | Out-Null
                $changed = $true
            }
        }
        $results.Add([pscustomobject]@{
            Id          = $forwardingProfile.id
            TrafficType = $trafficType
            State       = $desired
            Changed     = $changed
        })
    }
    return $results.ToArray()
}

function Get-GsaApplicationByDisplayName {
    param([Parameter(Mandatory)][string]$DisplayName)

    $escaped = $DisplayName.Replace("'", "''")
    $encodedFilter = [uri]::EscapeDataString("displayName eq '$escaped'")
    $apps = @(Get-GsaGraphCollection -Uri "/v1.0/applications?`$filter=$encodedFilter&`$select=id,appId,displayName")
    if ($apps.Count -gt 1) {
        throw "Multiple applications named '$DisplayName' exist."
    }
    return $apps | Select-Object -First 1
}

function Get-GsaServicePrincipal {
    param([Parameter(Mandatory)][string]$AppId)

    $encodedFilter = [uri]::EscapeDataString("appId eq '$AppId'")
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        $items = @(Get-GsaGraphCollection -Uri "/v1.0/servicePrincipals?`$filter=$encodedFilter&`$select=id,appId,appRoles")
        if ($items.Count -eq 1) {
            return $items[0]
        }
        Start-Sleep -Seconds 5
    }
    throw "Service principal for appId '$AppId' did not become available."
}

function Set-GsaPrivateApplication {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('quickaccessapp', 'nonwebapp')]
        [string]$ApplicationType,
        [Parameter(Mandatory)]
        [string]$DisplayName,
        [Parameter(Mandatory)]
        [guid]$ConnectorGroupId,
        [Parameter(Mandatory)]
        [string[]]$Destinations,
        [Parameter(Mandatory)]
        [object[]]$Ports,
        [ValidateSet('tcp', 'udp', 'tcp,udp')]
        [string]$Protocol = 'tcp',
        [guid]$PilotGroupId,
        [switch]$AllowAdditionalSegments,
        [switch]$AllowAdditionalAssignments
    )

    Assert-GsaPreviewGate -Feature 'Global Secure Access Quick Access and Private Access' -Enabled $true
    $normalizedPorts = ConvertTo-GsaNormalizedPort -Value $Ports
    $normalizedDestinations = @($Destinations | ForEach-Object { Get-GsaNormalizedDestination -Value $_ })
    if ($normalizedDestinations.Count -eq 0) {
        throw 'At least one destination is required.'
    }

    $connector = Invoke-MgGraphRequest -Method GET -Uri "/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$ConnectorGroupId" -OutputType PSObject
    $connectors = @(Get-GsaGraphCollection -Uri "/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$ConnectorGroupId/members")
    $activeConnectors = @($connectors | Where-Object { $_.status -eq 'active' })
    if ($activeConnectors.Count -eq 0) {
        throw "Connector group '$($connector.name)' has no active connectors. Install or restore a connector before configuring Private Access."
    }
    $application = Get-GsaApplicationByDisplayName -DisplayName $DisplayName
    $created = $false
    if (-not $application) {
        if (-not $PSCmdlet.ShouldProcess($DisplayName, 'Instantiate Private Access application template')) {
            return
        }
        $body = @{ displayName = $DisplayName } | ConvertTo-Json
        $result = Invoke-MgGraphRequest -Method POST -Uri '/v1.0/applicationTemplates/8adf8e6e-67b2-4cf2-a259-e3dc5476c621/instantiate' -Body $body -ContentType 'application/json' -OutputType PSObject
        $application = $result.application
        $created = $true
    }

    $state = Invoke-MgGraphRequest -Method GET -Uri "/beta/applications/$($application.id)?`$select=id,appId,displayName,onPremisesPublishing" -OutputType PSObject
    if (
        $state.onPremisesPublishing.applicationType -ne $ApplicationType -or
        $state.onPremisesPublishing.isAccessibleViaZTNAClient -ne $true
    ) {
        $body = @{
            onPremisesPublishing = @{
                applicationType              = $ApplicationType
                isAccessibleViaZTNAClient    = $true
            }
        } | ConvertTo-Json -Depth 5
        if ($PSCmdlet.ShouldProcess($DisplayName, "Set application type '$ApplicationType'")) {
            Invoke-MgGraphRequest -Method PATCH -Uri "/beta/applications/$($application.id)" -Body $body -ContentType 'application/json' | Out-Null
        }
    }

    $connectorRef = $null
    try {
        $connectorRef = Invoke-MgGraphRequest -Method GET -Uri "/beta/applications/$($application.id)/connectorGroup?`$select=id,name" -OutputType PSObject
    } catch {
        if ($_.Exception.Message -notmatch '404|Not Found') {
            throw
        }
    }
    if (-not $connectorRef -or $connectorRef.id -ne [string]$ConnectorGroupId) {
        $body = @{
            '@odata.id' = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$ConnectorGroupId"
        } | ConvertTo-Json
        if ($PSCmdlet.ShouldProcess($DisplayName, "Assign connector group '$($connector.name)'")) {
            Invoke-MgGraphRequest -Method PUT -Uri "/beta/applications/$($application.id)/connectorGroup/`$ref" -Body $body -ContentType 'application/json' | Out-Null
        }
    }

    $segmentUri = "/beta/applications/$($application.id)/onPremisesPublishing/segmentsConfiguration/microsoft.graph.ipSegmentConfiguration/applicationSegments"
    $existingSegments = @(Get-GsaGraphCollection -Uri $segmentUri)
    $existingKeys = @(
        $existingSegments |
            ForEach-Object {
                Get-GsaSegmentKey -DestinationType $_.destinationType -DestinationHost $_.destinationHost -Ports @($_.ports) -Protocol $_.protocol
            }
    )
    $desiredKeys = @(
        $normalizedDestinations | ForEach-Object {
            Get-GsaSegmentKey -DestinationType $_.Type -DestinationHost $_.Host -Ports $normalizedPorts -Protocol $Protocol
        }
    )
    $additionalSegments = @($existingKeys | Where-Object { $_ -notin $desiredKeys })
    if ($additionalSegments.Count -gt 0 -and -not $AllowAdditionalSegments) {
        throw "Application '$DisplayName' contains segments outside the desired configuration: $($additionalSegments -join '; '). Review them manually or explicitly allow additional segments."
    }

    $added = [System.Collections.Generic.List[string]]::new()
    foreach ($destination in $normalizedDestinations) {
        $key = Get-GsaSegmentKey -DestinationType $destination.Type -DestinationHost $destination.Host -Ports $normalizedPorts -Protocol $Protocol
        if ($key -in $existingKeys) {
            continue
        }
        $body = @{
            destinationHost = $destination.Host
            destinationType = $destination.Type
            port            = 0
            ports           = $normalizedPorts
            protocol        = $Protocol
        } | ConvertTo-Json -Depth 5
        if ($PSCmdlet.ShouldProcess($DisplayName, "Add segment '$key'")) {
            Invoke-MgGraphRequest -Method POST -Uri $segmentUri -Body $body -ContentType 'application/json' | Out-Null
            $added.Add($key)
        }
    }

    $servicePrincipal = Get-GsaServicePrincipal -AppId $application.appId
    $assignedPrincipalIds = @()
    if ($PilotGroupId -ne [guid]::Empty) {
        $userRole = @($servicePrincipal.appRoles | Where-Object {
            $_.displayName -eq 'User' -and $_.isEnabled -and 'User' -in $_.allowedMemberTypes
        }) | Select-Object -First 1
        if (-not $userRole) {
            throw "The User role is not available on '$DisplayName'."
        }

        $assignments = @(Get-GsaGraphCollection -Uri "/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignedTo")
        $roleAssignments = @($assignments | Where-Object { $_.appRoleId -eq $userRole.id })
        $assignedPrincipalIds = @($roleAssignments | Select-Object -ExpandProperty principalId)
        $additionalAssignments = @($roleAssignments | Where-Object { $_.principalId -ne [string]$PilotGroupId })
        if ($additionalAssignments.Count -gt 0 -and -not $AllowAdditionalAssignments) {
            throw "Application '$DisplayName' has additional User-role assignments: $($additionalAssignments.principalId -join ', '). Review them manually or explicitly allow additional assignments."
        }
        $existingAssignment = @($roleAssignments | Where-Object { $_.principalId -eq [string]$PilotGroupId })
        if ($existingAssignment.Count -eq 0) {
            $body = @{
                principalId = [string]$PilotGroupId
                resourceId  = $servicePrincipal.id
                appRoleId   = $userRole.id
            } | ConvertTo-Json
            if ($PSCmdlet.ShouldProcess($DisplayName, "Assign pilot group '$PilotGroupId'")) {
                Invoke-MgGraphRequest -Method POST -Uri "/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignedTo" -Body $body -ContentType 'application/json' | Out-Null
            }
        }
    }

    return [pscustomobject]@{
        DisplayName        = $DisplayName
        ApplicationId      = $application.id
        AppId              = $application.appId
        ServicePrincipalId = $servicePrincipal.id
        ConnectorGroupId   = [string]$ConnectorGroupId
        Created            = $created
        AddedSegments      = $added.ToArray()
        AdditionalSegments = $additionalSegments
        AssignedPrincipalIds = $assignedPrincipalIds
    }
}

function ConvertTo-GsaWebCategoryName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Name
    )

    process {
        $trimmed = $Name.Trim()
        $alias = $trimmed -replace '[^a-zA-Z0-9]', ''
        if ($alias -match '^(?i:socialmedia|socialnetworking)$') {
            return 'SocialNetworking'
        }
        if ($trimmed -notmatch '^[A-Za-z][A-Za-z0-9]*$') {
            throw "Web category '$Name' is not a canonical Graph identifier. Use a value from the documented Global Secure Access category list, such as SocialNetworking."
        }
        return $trimmed
    }
}

function Get-GsaSingleNamedGraphObject {
    param(
        [Parameter(Mandatory)][string]$CollectionUri,
        [Parameter(Mandatory)][string]$PropertyName,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ObjectDescription
    )

    $escaped = $Name.Replace("'", "''")
    $encodedFilter = [uri]::EscapeDataString("$PropertyName eq '$escaped'")
    $namedObjects = @(Get-GsaGraphCollection -Uri "$CollectionUri`?`$filter=$encodedFilter")
    if ($namedObjects.Count -gt 1) {
        throw "Multiple $ObjectDescription objects named '$Name' exist."
    }
    return $namedObjects | Select-Object -First 1
}

function Assert-GsaInternetFilteringPolicy {
    param(
        [Parameter(Mandatory)][object]$Policy,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Categories
    )

    if ($Policy.action -ne 'block') {
        throw "Filtering policy '$Name' exists with action '$($Policy.action)' instead of 'block'."
    }
    $rules = @($Policy.policyRules)
    $webRules = @($rules | Where-Object {
        ($_.PSObject.Properties['@odata.type'] -and $_.'@odata.type' -eq '#microsoft.graph.networkaccess.webCategoryFilteringRule') -or
        ($_.PSObject.Properties['ruleType'] -and $_.ruleType -eq 'webCategory')
    })
    if ($rules.Count -ne 1 -or $webRules.Count -ne 1) {
        throw "Filtering policy '$Name' contains rules outside the single managed web-category rule. Review the policy manually; no rules were removed."
    }
    $existingCategories = @($webRules[0].destinations | ForEach-Object { $_.name } | Sort-Object -Unique)
    if (@(Compare-Object -ReferenceObject $Categories -DifferenceObject $existingCategories).Count -gt 0) {
        throw "Filtering policy '$Name' categories differ from the requested categories. Existing rules were preserved."
    }
}

function Assert-GsaInternetSecurityProfile {
    param(
        [Parameter(Mandatory)][object]$SecurityProfile,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Priority
    )

    if ($SecurityProfile.state -ne 'enabled' -or [int]$SecurityProfile.priority -ne $Priority) {
        throw "Filtering profile '$Name' exists with state '$($SecurityProfile.state)' and priority '$($SecurityProfile.priority)'; expected enabled/$Priority."
    }
}

function Assert-GsaInternetPolicyLinkSet {
    param(
        [Parameter(Mandatory)][object[]]$Links,
        [Parameter(Mandatory)][string]$PolicyId,
        [Parameter(Mandatory)][string]$PolicyName,
        [Parameter(Mandatory)][string]$SecurityProfileName,
        [Parameter(Mandatory)][int]$Priority
    )

    $matchingLinks = @($Links | Where-Object { $_.policy.id -eq $PolicyId })
    if ($matchingLinks.Count -ne 1) {
        throw "Expected exactly one link from filtering policy '$PolicyName' to '$SecurityProfileName'; found $($matchingLinks.Count)."
    }
    if ($Links.Count -ne 1) {
        throw "Filtering profile '$SecurityProfileName' contains unmanaged policy links. Review the profile manually; no links were removed."
    }
    if (
        [int]$matchingLinks[0].priority -ne $Priority -or
        $matchingLinks[0].state -ne 'enabled' -or
        $matchingLinks[0].loggingState -ne 'enabled'
    ) {
        throw "The managed policy link in '$SecurityProfileName' has incompatible priority, state, or logging state."
    }
}

function Assert-GsaInternetConditionalAccessPolicy {
    param(
        [Parameter(Mandatory)][object]$ConditionalAccessPolicy,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$SecurityProfileId
    )

    $internetResourceAppId = '5dc48733-b5df-475c-a49b-fa307ef00853'
    $includedPrincipals = @(
        @($ConditionalAccessPolicy.conditions.users.includeUsers) +
        @($ConditionalAccessPolicy.conditions.users.includeGroups) +
        @($ConditionalAccessPolicy.conditions.users.includeRoles)
    )
    $includedApplications = @($ConditionalAccessPolicy.conditions.applications.includeApplications)
    $sessionControl = if (
        $ConditionalAccessPolicy.PSObject.Properties['sessionControls'] -and
        $null -ne $ConditionalAccessPolicy.sessionControls -and
        $ConditionalAccessPolicy.sessionControls.PSObject.Properties['globalSecureAccessFilteringProfile']
    ) {
        $ConditionalAccessPolicy.sessionControls.globalSecureAccessFilteringProfile
    } else {
        $null
    }
    if (
        $ConditionalAccessPolicy.state -ne 'disabled' -or
        $includedPrincipals.Count -ne 0 -or
        $includedApplications.Count -ne 1 -or
        $includedApplications[0] -ne $internetResourceAppId -or
        $null -eq $sessionControl -or
        -not $sessionControl.isEnabled -or
        $sessionControl.profileId -ne $SecurityProfileId
    ) {
        throw "Conditional Access policy '$Name' differs from the disabled, unassigned managed configuration. It was not changed."
    }
}

function Test-GsaInternetBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$BlockedCategories,
        [string]$SecurityProfileName = 'GSA POC Baseline Security Profile',
        [string]$ConditionalAccessPolicyName = 'GSA POC Baseline Internet Access',
        [ValidateRange(1, 65000)][int]$SecurityProfilePriority = 100,
        [ValidateRange(1, 65000)][int]$PolicyLinkPriority = 100
    )

    Assert-GsaPreviewGate -Feature 'Global Secure Access Internet filtering baseline validation' -Enabled $true
    $categories = @($BlockedCategories | ForEach-Object { ConvertTo-GsaWebCategoryName -Name $_ } | Sort-Object -Unique)
    if ($categories.Count -eq 0) {
        throw 'At least one reviewed web category is required.'
    }

    $policy = Get-GsaSingleNamedGraphObject -CollectionUri '/beta/networkAccess/filteringPolicies' -PropertyName name -Name $Name -ObjectDescription 'filtering policy'
    if (-not $policy) { throw "Filtering policy '$Name' does not exist." }
    $policy = Invoke-MgGraphRequest -Method GET -Uri "/beta/networkAccess/filteringPolicies/$($policy.id)?`$expand=policyRules" -OutputType PSObject
    Assert-GsaInternetFilteringPolicy -Policy $policy -Name $Name -Categories $categories

    $securityProfile = Get-GsaSingleNamedGraphObject -CollectionUri '/beta/networkAccess/filteringProfiles' -PropertyName name -Name $SecurityProfileName -ObjectDescription 'filtering profile'
    if (-not $securityProfile) { throw "Filtering profile '$SecurityProfileName' does not exist." }
    Assert-GsaInternetSecurityProfile -SecurityProfile $securityProfile -Name $SecurityProfileName -Priority $SecurityProfilePriority

    $links = @(Get-GsaGraphCollection -Uri "/beta/networkAccess/filteringProfiles/$($securityProfile.id)/policies")
    Assert-GsaInternetPolicyLinkSet -Links $links -PolicyId $policy.id -PolicyName $Name -SecurityProfileName $SecurityProfileName -Priority $PolicyLinkPriority

    $caPolicy = Get-GsaSingleNamedGraphObject -CollectionUri '/beta/identity/conditionalAccess/policies' -PropertyName displayName -Name $ConditionalAccessPolicyName -ObjectDescription 'Conditional Access policy'
    if (-not $caPolicy) { throw "Conditional Access policy '$ConditionalAccessPolicyName' does not exist." }
    Assert-GsaInternetConditionalAccessPolicy -ConditionalAccessPolicy $caPolicy -Name $ConditionalAccessPolicyName -SecurityProfileId $securityProfile.id

    return [pscustomobject]@{
        FilteringPolicyId = $policy.id
        SecurityProfileId = $securityProfile.id
        ConditionalAccessPolicyId = $caPolicy.id
        BlockedCategories = $categories
    }
}

function Set-GsaInternetBaseline {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string[]]$BlockedCategories,
        [string]$SecurityProfileName = 'GSA POC Baseline Security Profile',
        [string]$ConditionalAccessPolicyName = 'GSA POC Baseline Internet Access',
        [ValidateRange(1, 65000)]
        [int]$SecurityProfilePriority = 100,
        [ValidateRange(1, 65000)]
        [int]$PolicyLinkPriority = 100
    )

    Assert-GsaPreviewGate -Feature 'Global Secure Access Internet filtering baseline' -Enabled $true
    if ($BlockedCategories.Count -eq 0) {
        throw 'At least one reviewed web category is required.'
    }
    $categories = @(
        $BlockedCategories |
            ForEach-Object { ConvertTo-GsaWebCategoryName -Name $_ } |
            Sort-Object -Unique
    )

    $policy = Get-GsaSingleNamedGraphObject -CollectionUri '/beta/networkAccess/filteringPolicies' -PropertyName name -Name $Name -ObjectDescription 'filtering policy'
    if (-not $policy) {
        $body = @{
            '@odata.type' = '#microsoft.graph.networkaccess.filteringPolicy'
            name          = $Name
            description   = 'POC baseline created by azd-global-secure-access'
            action        = 'block'
            policyRules   = @(
                @{
                    '@odata.type' = '#microsoft.graph.networkaccess.webCategoryFilteringRule'
                    name          = 'Blocked categories'
                    ruleType      = 'webCategory'
                    destinations  = @($categories | ForEach-Object {
                        @{
                            '@odata.type' = '#microsoft.graph.networkaccess.webCategory'
                            name          = $_
                        }
                    })
                }
            )
        } | ConvertTo-Json -Depth 10
        if ($PSCmdlet.ShouldProcess($Name, 'Create Internet filtering policy')) {
            $policy = Invoke-MgGraphRequest -Method POST -Uri '/beta/networkAccess/filteringPolicies' -Body $body -ContentType 'application/json' -OutputType PSObject
        } else {
            return [pscustomobject]@{ Planned = $true; FilteringPolicyName = $Name; SecurityProfileName = $SecurityProfileName; ConditionalAccessPolicyName = $ConditionalAccessPolicyName }
        }
    } else {
        $policy = Invoke-MgGraphRequest -Method GET -Uri "/beta/networkAccess/filteringPolicies/$($policy.id)?`$expand=policyRules" -OutputType PSObject
        Assert-GsaInternetFilteringPolicy -Policy $policy -Name $Name -Categories $categories
    }

    $securityProfile = Get-GsaSingleNamedGraphObject -CollectionUri '/beta/networkAccess/filteringProfiles' -PropertyName name -Name $SecurityProfileName -ObjectDescription 'filtering profile'
    if (-not $securityProfile) {
        $body = @{
            name        = $SecurityProfileName
            description = 'POC security profile created by azd-global-secure-access; activation is controlled by Conditional Access.'
            state       = 'enabled'
            priority    = $SecurityProfilePriority
            policies    = @()
        } | ConvertTo-Json -Depth 5
        if ($PSCmdlet.ShouldProcess($SecurityProfileName, 'Create custom Internet security profile')) {
            $securityProfile = Invoke-MgGraphRequest -Method POST -Uri '/beta/networkAccess/filteringProfiles' -Body $body -ContentType 'application/json' -OutputType PSObject
        } else {
            return [pscustomobject]@{ Planned = $true; FilteringPolicyName = $Name; SecurityProfileName = $SecurityProfileName; ConditionalAccessPolicyName = $ConditionalAccessPolicyName }
        }
    } else {
        Assert-GsaInternetSecurityProfile -SecurityProfile $securityProfile -Name $SecurityProfileName -Priority $SecurityProfilePriority
    }

    $links = @(Get-GsaGraphCollection -Uri "/beta/networkAccess/filteringProfiles/$($securityProfile.id)/policies")
    $matchingLinks = @($links | Where-Object { $_.policy.id -eq $policy.id })
    if ($matchingLinks.Count -gt 1) {
        throw "Filtering policy '$Name' is linked to '$SecurityProfileName' more than once."
    }
    if ($matchingLinks.Count -eq 0) {
        if ($links.Count -gt 0) {
            throw "Filtering profile '$SecurityProfileName' contains unmanaged policy links. Review the profile manually; no links were added or removed."
        }
        $body = @{
            '@odata.type' = '#microsoft.graph.networkaccess.filteringPolicyLink'
            priority      = $PolicyLinkPriority
            state         = 'enabled'
            loggingState  = 'enabled'
            policy        = @{
                '@odata.type' = '#microsoft.graph.networkaccess.filteringPolicy'
                id            = $policy.id
            }
        } | ConvertTo-Json -Depth 6
        if ($PSCmdlet.ShouldProcess($Name, "Link policy to custom security profile '$SecurityProfileName'")) {
            Invoke-MgGraphRequest -Method POST -Uri "/beta/networkAccess/filteringProfiles/$($securityProfile.id)/policies" -Body $body -ContentType 'application/json' | Out-Null
        } else {
            return [pscustomobject]@{ Planned = $true; FilteringPolicyName = $Name; SecurityProfileName = $SecurityProfileName; ConditionalAccessPolicyName = $ConditionalAccessPolicyName }
        }
    } else {
        Assert-GsaInternetPolicyLinkSet -Links $links -PolicyId $policy.id -PolicyName $Name -SecurityProfileName $SecurityProfileName -Priority $PolicyLinkPriority
    }

    $caPolicy = Get-GsaSingleNamedGraphObject -CollectionUri '/beta/identity/conditionalAccess/policies' -PropertyName displayName -Name $ConditionalAccessPolicyName -ObjectDescription 'Conditional Access policy'
    $internetResourceAppId = '5dc48733-b5df-475c-a49b-fa307ef00853'
    if (-not $caPolicy) {
        $body = @{
            displayName = $ConditionalAccessPolicyName
            state       = 'disabled'
            conditions  = @{
                applications = @{ includeApplications = @($internetResourceAppId) }
                users        = @{
                    includeUsers  = @()
                    includeGroups = @()
                    includeRoles  = @()
                    excludeUsers  = @()
                    excludeGroups = @()
                    excludeRoles  = @()
                }
            }
            sessionControls = @{
                globalSecureAccessFilteringProfile = @{
                    '@odata.type' = '#microsoft.graph.globalSecureAccessFilteringProfileSessionControl'
                    profileId     = $securityProfile.id
                    isEnabled     = $true
                }
            }
        } | ConvertTo-Json -Depth 10
        if ($PSCmdlet.ShouldProcess($ConditionalAccessPolicyName, 'Create disabled and unassigned Conditional Access policy')) {
            $caPolicy = Invoke-MgGraphRequest -Method POST -Uri '/beta/identity/conditionalAccess/policies' -Body $body -ContentType 'application/json' -OutputType PSObject
        } else {
            return [pscustomobject]@{ Planned = $true; FilteringPolicyName = $Name; SecurityProfileName = $SecurityProfileName; ConditionalAccessPolicyName = $ConditionalAccessPolicyName }
        }
    } else {
        Assert-GsaInternetConditionalAccessPolicy -ConditionalAccessPolicy $caPolicy -Name $ConditionalAccessPolicyName -SecurityProfileId $securityProfile.id
    }

    return [pscustomobject]@{
        FilteringPolicyId         = $policy.id
        FilteringPolicyName       = $Name
        BlockedCategories         = $categories
        SecurityProfileId         = $securityProfile.id
        SecurityProfileName       = $SecurityProfileName
        ConditionalAccessPolicyId = $caPolicy.id
        ConditionalAccessPolicyName = $ConditionalAccessPolicyName
        ConditionalAccessState    = 'disabled'
        AssignedPrincipals        = @()
    }
}

Export-ModuleMember -Function @(
    'Enable-GsaTenantOnboarding',
    'Get-GsaTenantStatus',
    'Set-GsaForwardingProfile',
    'Set-GsaInternetBaseline',
    'Set-GsaPrivateApplication',
    'Test-GsaInternetBaseline'
)
