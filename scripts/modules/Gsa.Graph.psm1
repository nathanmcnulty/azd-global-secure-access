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

function Set-GsaInternetBaseline {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string[]]$BlockedCategories,
        [switch]$AcknowledgeTenantWideImpact
    )

    Assert-GsaPreviewGate -Feature 'Global Secure Access Internet filtering baseline' -Enabled $true
    if (-not $AcknowledgeTenantWideImpact) {
        throw 'The built-in baseline applies to all traffic routed through GSA. Set the lab-mode acknowledgement before creating or linking a policy.'
    }
    if ($BlockedCategories.Count -eq 0) {
        throw 'At least one reviewed web category is required.'
    }

    $escaped = $Name.Replace("'", "''")
    $encodedFilter = [uri]::EscapeDataString("name eq '$escaped'")
    $policies = @(Get-GsaGraphCollection -Uri "/beta/networkAccess/filteringPolicies?`$filter=$encodedFilter")
    if ($policies.Count -gt 1) {
        throw "Multiple filtering policies named '$Name' exist."
    }
    $policy = $policies | Select-Object -First 1
    if (-not $policy) {
        $body = @{
            '@odata.type' = '#microsoft.graph.networkaccess.filteringPolicy'
            name          = $Name
            description   = 'Lab baseline created by azd-global-secure-access'
            action        = 'block'
            policyRules   = @(
                @{
                    '@odata.type' = '#microsoft.graph.networkaccess.webCategoryFilteringRule'
                    name          = 'Blocked categories'
                    ruleType      = 'webCategory'
                    destinations  = @($BlockedCategories | ForEach-Object {
                        @{
                            '@odata.type' = '#microsoft.graph.networkaccess.webCategory'
                            name          = $_
                        }
                    })
                }
            )
        } | ConvertTo-Json -Depth 10
        if ($PSCmdlet.ShouldProcess($Name, 'Create tenant-wide Internet filtering policy')) {
            $policy = Invoke-MgGraphRequest -Method POST -Uri '/beta/networkAccess/filteringPolicies' -Body $body -ContentType 'application/json' -OutputType PSObject
        }
    }

    $profiles = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/filteringProfiles')
    $baseline = @($profiles | Where-Object { $_.priority -eq 65000 })
    if ($baseline.Count -ne 1) {
        throw "Expected one built-in baseline filtering profile at priority 65000, found $($baseline.Count)."
    }
    $links = @(Get-GsaGraphCollection -Uri "/beta/networkAccess/filteringProfiles/$($baseline[0].id)/policies")
    if (@($links | Where-Object { $_.policy.id -eq $policy.id }).Count -eq 0) {
        $body = @{
            '@odata.type' = '#microsoft.graph.networkaccess.filteringPolicyLink'
            priority      = 100
            state         = 'enabled'
            loggingState  = 'enabled'
            policy        = @{
                '@odata.type' = '#microsoft.graph.networkaccess.filteringPolicy'
                id            = $policy.id
            }
        } | ConvertTo-Json -Depth 6
        if ($PSCmdlet.ShouldProcess($Name, 'Link policy to built-in baseline filtering profile')) {
            Invoke-MgGraphRequest -Method POST -Uri "/beta/networkAccess/filteringProfiles/$($baseline[0].id)/policies" -Body $body -ContentType 'application/json' | Out-Null
        }
    }
    return $policy
}

Export-ModuleMember -Function @(
    'Enable-GsaTenantOnboarding',
    'Get-GsaTenantStatus',
    'Set-GsaForwardingProfile',
    'Set-GsaInternetBaseline',
    'Set-GsaPrivateApplication'
)
