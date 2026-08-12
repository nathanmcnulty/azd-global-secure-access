Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Gsa.State.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Gsa.Readiness.psm1') -Force

$script:ValidRemoteNetworkRegions = @(
    'australiaEast', 'australiaSouthEast', 'brazilSouth', 'canadaCentral', 'canadaEast', 'centralIndia',
    'centralUS', 'eastUS', 'franceCentral', 'franceSouth', 'germanyWestCentral', 'israelCentral', 'italyNorth',
    'japanEast', 'japanWest', 'koreaCentral', 'koreaSouth', 'northCentralUS', 'northEurope', 'polandCentral',
    'southAfricaNorth', 'southAfricaWest', 'southCentralUS', 'southEastAsia', 'southIndia', 'swedenCentral',
    'switzerlandNorth', 'uaeNorth', 'ukSouth', 'westCentralUS', 'westEurope', 'westUS', 'westUS2', 'westUS3'
)
$script:ValidBandwidth = @('mbps250', 'mbps500', 'mbps750', 'mbps1000')
$script:ReservedAsn = @(8075, 8076, 12076, 23456, 65476, 65517, 65518, 65519, 65520)

function Test-GsaPublicIpv4Address {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Address)

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }

    $bytes = $parsed.GetAddressBytes()
    if (
        $bytes[0] -in 0, 10, 127 -or
        ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) -or
        ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
        ($bytes[0] -eq 198 -and $bytes[1] -in 18, 19) -or
        $bytes[0] -ge 224
    ) {
        return $false
    }
    return $true
}

function Test-GsaBgpIpv4Address {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Address)

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }
    $bytes = $parsed.GetAddressBytes()
    return -not (
        $bytes[0] -eq 0 -or $bytes[0] -eq 127 -or $bytes[0] -ge 224 -or
        ($bytes[0] -eq 255 -and $bytes[1] -eq 255 -and $bytes[2] -eq 255 -and $bytes[3] -eq 255)
    )
}

function Test-GsaAsnValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][long]$Asn)

    return $Asn -ge 1 -and $Asn -le 65534 -and $Asn -notin $script:ReservedAsn -and -not ($Asn -ge 64496 -and $Asn -le 64511)
}

function Get-GsaRemoteNetworkBandwidthAllocation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$LicenseCount)

    if ($LicenseCount -lt 50) { return 0 }
    if ($LicenseCount -lt 100) { return 500 }
    if ($LicenseCount -lt 500) { return 1000 }
    if ($LicenseCount -lt 1000) { return 2000 }
    if ($LicenseCount -lt 1500) { return 3500 }
    if ($LicenseCount -lt 2000) { return 4000 }
    if ($LicenseCount -lt 2500) { return 4500 }
    if ($LicenseCount -lt 3000) { return 5000 }
    if ($LicenseCount -lt 3500) { return 5500 }
    if ($LicenseCount -lt 4000) { return 6000 }
    if ($LicenseCount -lt 4500) { return 6500 }
    if ($LicenseCount -lt 5000) { return 7000 }
    if ($LicenseCount -lt 5500) { return 10000 }
    if ($LicenseCount -lt 6000) { return 10500 }
    if ($LicenseCount -lt 6500) { return 11000 }
    if ($LicenseCount -lt 7000) { return 11500 }
    if ($LicenseCount -lt 7500) { return 12000 }
    if ($LicenseCount -lt 8000) { return 12500 }
    if ($LicenseCount -lt 8500) { return 13000 }
    if ($LicenseCount -lt 9000) { return 13500 }
    if ($LicenseCount -lt 9500) { return 14000 }
    if ($LicenseCount -lt 10000) { return 14500 }
    return 35000 + ([math]::Floor(($LicenseCount - 10000) / 500) * 500)
}

function Get-GsaRemoteNetworkLicenseIndicator {
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$SubscribedSkus)

    $qualifying = @($SubscribedSkus | Where-Object {
        $partNumber = [string]$_.skuPartNumber
        $servicePlanNames = @($_.servicePlans | ForEach-Object { [string]$_.servicePlanName })
        $partNumber -match '(?i)AAD_PREMIUM|ENTRA.*(INTERNET|SUITE)' -or
        @($servicePlanNames | Where-Object { $_ -match '(?i)AAD_PREMIUM|NETWORKACCESS|ENTRA.*INTERNET' }).Count -gt 0
    } | ForEach-Object {
        [pscustomobject][ordered]@{
            skuId = [string]$_.skuId
            skuPartNumber = [string]$_.skuPartNumber
            enabledUnits = if ($_.prepaidUnits -and $_.prepaidUnits.PSObject.Properties['enabled']) { [int]$_.prepaidUnits.enabled } else { 0 }
            consumedUnits = if ($_.PSObject.Properties['consumedUnits']) { [int]$_.consumedUnits } else { 0 }
        }
    } | Sort-Object skuPartNumber, skuId)
    $conservativeCount = if ($qualifying.Count) { [int](($qualifying | Measure-Object enabledUnits -Maximum).Maximum) } else { 0 }
    return [pscustomobject][ordered]@{
        qualifyingSkus = $qualifying
        conservativePurchasedSeatIndicator = $conservativeCount
        advisoryOnly = $true
        evidence = 'The maximum enabled unit count is used to avoid double-counting overlapping bundles. SKU inventory cannot prove assignment, entitlement, or remote-network feature availability.'
    }
}

function Test-GsaTunnelConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$TunnelConfiguration)

    $errors = [System.Collections.Generic.List[string]]::new()
    $type = [string]$TunnelConfiguration.'@odata.type'
    if ($type -eq '#microsoft.graph.networkaccess.tunnelConfigurationIKEv2Default') {
        return @()
    }
    if ($type -ne '#microsoft.graph.networkaccess.tunnelConfigurationIKEv2Custom') {
        return @("Unsupported tunnel configuration type '$type'. Only documented IKEv2 default or custom types are accepted.")
    }

    $validDhGroups = @('group2', 'group14', 'group24', 'ecp256', 'ecp384')
    $validIkeEncryption = @('aes128', 'aes192', 'aes256', 'gcmAes128', 'gcmAes192', 'gcmAes256')
    $validIkeIntegrity = @('sha256', 'sha384', 'gcmAes128', 'gcmAes192', 'gcmAes256')
    if ([string]$TunnelConfiguration.dhGroup -notin $validDhGroups) { $errors.Add("Unsupported IKE Diffie-Hellman group '$($TunnelConfiguration.dhGroup)'.") }
    if ([string]$TunnelConfiguration.ikeEncryption -notin $validIkeEncryption) { $errors.Add("Unsupported IKE encryption '$($TunnelConfiguration.ikeEncryption)'.") }
    if ([string]$TunnelConfiguration.ikeIntegrity -notin $validIkeIntegrity) { $errors.Add("Unsupported IKE integrity '$($TunnelConfiguration.ikeIntegrity)'.") }
    $validIpsecPairs = @('gcmAes128|gcmAes128', 'gcmAes192|gcmAes192', 'gcmAes256|gcmAes256', 'none|sha256')
    $pair = "$([string]$TunnelConfiguration.ipSecEncryption)|$([string]$TunnelConfiguration.ipSecIntegrity)"
    if ($pair -notin $validIpsecPairs) { $errors.Add("Unsupported IPsec encryption/integrity pair '$pair'.") }
    if ([int]$TunnelConfiguration.saLifeTimeSeconds -le 300) { $errors.Add('Custom IKE SA lifetime must be greater than 300 seconds.') }
    return $errors.ToArray()
}

function Get-GsaRemoteNetworkValidation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Configuration)

    $errors = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    if ([string]$Configuration.region -notin $script:ValidRemoteNetworkRegions) { $errors.Add("Region '$($Configuration.region)' is not in the documented remote-network region list.") }
    $link = $Configuration.deviceLink
    if (-not (Test-GsaPublicIpv4Address -Address ([string]$link.ipAddress))) { $errors.Add('Device IP address must be a public IPv4 address. For a CPE behind NAT, use the upstream router public IP.') }
    if (-not (Test-GsaBgpIpv4Address -Address ([string]$link.bgpConfiguration.localIpAddress))) { $errors.Add('Local BGP address is invalid or reserved.') }
    if (-not (Test-GsaBgpIpv4Address -Address ([string]$link.bgpConfiguration.peerIpAddress))) { $errors.Add('Peer BGP address is invalid or reserved.') }
    if ([string]$link.bgpConfiguration.localIpAddress -eq [string]$link.bgpConfiguration.peerIpAddress) { $errors.Add('Local and peer BGP addresses must differ.') }
    if (-not (Test-GsaAsnValue -Asn ([long]$link.bgpConfiguration.asn))) { $errors.Add("ASN '$($link.bgpConfiguration.asn)' is outside the documented 2-byte range or is reserved.") }
    if ([string]$link.bandwidthCapacityInMbps -notin $script:ValidBandwidth) { $errors.Add('Bandwidth must be mbps250, mbps500, mbps750, or mbps1000.') }
    $redundancy = [string]$link.redundancyConfiguration.redundancyTier
    if ($redundancy -notin 'noRedundancy', 'zoneRedundancy') { $errors.Add("Unknown redundancy tier '$redundancy'.") }
    if ($redundancy -eq 'zoneRedundancy') {
        $zoneAddress = [string]$link.redundancyConfiguration.zoneLocalIpAddress
        if (-not (Test-GsaBgpIpv4Address -Address $zoneAddress) -or $zoneAddress -eq [string]$link.bgpConfiguration.localIpAddress) {
            $errors.Add('Zone-redundant local BGP address must be valid and different from the primary local BGP address.')
        }
    } else {
        $warnings.Add('Microsoft recommends at least two IPsec tunnels per location for high availability.')
    }
    foreach ($validationError in @(Test-GsaTunnelConfiguration -TunnelConfiguration $link.tunnelConfiguration)) { $errors.Add($validationError) }
    if (@($Configuration.forwardingProfileTypes).Count -gt 0) {
        $warnings.Add('Forwarding-profile associations are plan/report only. This template never changes an existing association automatically.')
    }
    return [pscustomobject][ordered]@{ valid = $errors.Count -eq 0; errors = $errors.ToArray(); warnings = $warnings.ToArray() }
}

function Get-GsaAssociationRisk {
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$ForwardingProfiles)

    $types = @($ForwardingProfiles | Where-Object { $null -ne $_ -and $_.PSObject.Properties['trafficForwardingType'] } | ForEach-Object {
        [string]$_.trafficForwardingType
    } | Where-Object { $_ } | Sort-Object -Unique)
    if ('private' -in $types) {
        return [pscustomobject][ordered]@{ severity = 'refuse'; detail = 'Private Access traffic profiles are not supported for remote networks.'; types = $types }
    }
    if (($types -contains 'm365') -xor ($types -contains 'internet')) {
        return [pscustomobject][ordered]@{ severity = 'refuse'; detail = 'Associating only Microsoft or only Internet traffic can silently drop the other traffic class at the gateway.'; types = $types }
    }
    if ($types.Count -eq 0) {
        return [pscustomobject][ordered]@{ severity = 'warning'; detail = 'No traffic profile is associated. The tunnel cannot acquire traffic until associations are reviewed manually.'; types = $types }
    }
    return [pscustomobject][ordered]@{ severity = 'info'; detail = 'Microsoft and Internet traffic profiles are both associated. Licensing and actual routing still require operator validation.'; types = $types }
}

function Get-GsaRemoteNetworkPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [Parameter(Mandatory)][object]$Inventory,
        [AllowNull()][object]$Manifest,
        [string]$AzureCloud = 'AzureCloud',
        [string]$GraphEnvironment = 'Global',
        [DateTimeOffset]$GeneratedAt = [DateTimeOffset]::UtcNow
    )

    Assert-GsaStateContentSafe -Value $Configuration
    $validation = Get-GsaRemoteNetworkValidation -Configuration $Configuration
    $networkMatches = @($Inventory.remoteNetworks | Where-Object name -eq $Configuration.name)
    $existing = $networkMatches | Select-Object -First 1
    $manifestResource = if ($existing -and $Manifest) {
        @($Manifest.resources | Where-Object { $_.kind -eq 'Microsoft.Graph/networkAccess/remoteNetwork' -and $_.id -eq $existing.id }) | Select-Object -First 1
    } else { $null }
    $ownership = if ($networkMatches.Count -gt 1) { 'unmanagedConflict' } elseif (-not $existing) { 'unclaimed' } elseif ($manifestResource -and $manifestResource.ownership -eq 'managed') { 'managed' } else { 'reused' }
    $disposition = if (-not $validation.valid) { 'blocked-invalid' } elseif ($AzureCloud -ne 'AzureCloud' -or $GraphEnvironment -ne 'Global') { 'blocked-unsupported-cloud' } elseif ($ownership -eq 'unclaimed') { 'eligible-create' } elseif ($ownership -eq 'managed') { 'inventory-managed-no-update' } else { 'blocked-existing-unmanaged' }
    $associations = if ($existing -and $existing.PSObject.Properties['forwardingProfiles']) { @($existing.forwardingProfiles) } else { @() }
    $inventoryProjection = [ordered]@{
        remoteNetworks = @($Inventory.remoteNetworks | Sort-Object id | ForEach-Object { ConvertTo-GsaCanonicalValue -Value $_ })
        deployments = @($Inventory.deployments | Sort-Object id | ForEach-Object { ConvertTo-GsaCanonicalValue -Value $_ })
        adaptiveAccess = ConvertTo-GsaCanonicalValue -Value $Inventory.adaptiveAccess
        namedLocations = @($Inventory.namedLocations | Sort-Object id | ForEach-Object { ConvertTo-GsaCanonicalValue -Value $_ })
        conditionalAccessPolicies = @($Inventory.conditionalAccessPolicies | Sort-Object id | ForEach-Object { ConvertTo-GsaCanonicalValue -Value $_ })
        licenseCount = if ($Inventory.PSObject.Properties['licenseCount']) { [int]$Inventory.licenseCount } else { 0 }
        licenseIndicators = if ($Inventory.PSObject.Properties['licenseIndicators']) { ConvertTo-GsaCanonicalValue -Value $Inventory.licenseIndicators } else { $null }
    }
    $identity = [ordered]@{
        schemaVersion = '1.0.0'
        apiContract = 'microsoftGraph-beta@2026-08'
        desired = ConvertTo-GsaCanonicalValue -Value $Configuration
        inventoryFingerprint = Get-GsaStateFingerprint -Value $inventoryProjection
        manifestFingerprint = if ($Manifest) { Get-GsaStateFingerprint -Value $Manifest } else { $null }
        azureCloud = $AzureCloud
        graphEnvironment = $GraphEnvironment
        ownership = $ownership
        disposition = $disposition
    }
    return [pscustomobject][ordered]@{
        schemaVersion = '1.0.0'
        planId = Get-GsaStateFingerprint -Value $identity
        generatedAt = $GeneratedAt.ToUniversalTime().ToString('O')
        expiresAt = $GeneratedAt.AddMinutes(30).ToUniversalTime().ToString('O')
        apiContract = $identity.apiContract
        mutationPerformed = $false
        azureCloud = $AzureCloud
        graphEnvironment = $GraphEnvironment
        targetOwnership = $ownership
        disposition = $disposition
        targetId = if ($existing) { [string]$existing.id } else { $null }
        desired = $identity.desired
        validation = $validation
        associationRisk = Get-GsaAssociationRisk -ForwardingProfiles $associations
        inventoryFingerprint = $identity.inventoryFingerprint
        manifestFingerprint = $identity.manifestFingerprint
        inventory = $inventoryProjection
        adaptiveAccessReadiness = Get-GsaAdaptiveAccessReadiness -AdaptiveAccess $inventoryProjection.adaptiveAccess `
            -NamedLocations $inventoryProjection.namedLocations -ConditionalAccessPolicies $inventoryProjection.conditionalAccessPolicies
        safeguards = @(
            'Creation only; existing remote networks, device links, and forwarding-profile associations are never mutated.',
            'A pre-shared key is accepted only as SecureString during explicit execution and is never written to plans, reports, state, logs, or fixtures.',
            'Router configuration and connector installation remain manual.',
            'Adaptive Access, source-IP restoration, compliant-network signaling, named locations, Conditional Access, and Universal CAE are read-only readiness surfaces.'
        )
    }
}

function Assert-GsaRemoteNetworkPlanCurrent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$CurrentPlan,
        [AllowNull()][object]$Manifest,
        [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow
    )

    if ($Now -gt [DateTimeOffset]::Parse([string]$Plan.expiresAt)) { throw 'The reviewed remote-network plan has expired.' }
    if ($Plan.planId -ne $CurrentPlan.planId -or $Plan.inventoryFingerprint -ne $CurrentPlan.inventoryFingerprint) { throw 'The reviewed remote-network plan is stale because current Graph state changed.' }
    $manifestFingerprint = if ($Manifest) { Get-GsaStateFingerprint -Value $Manifest } else { $null }
    if ($Plan.manifestFingerprint -ne $manifestFingerprint) { throw 'The ownership manifest changed after the remote-network plan was reviewed.' }
    if ($Plan.disposition -ne 'eligible-create') { throw "Plan disposition '$($Plan.disposition)' is not eligible for mutation." }
}

function Get-GsaAdaptiveAccessReadiness {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$AdaptiveAccess,
        [AllowEmptyCollection()][object[]]$NamedLocations,
        [AllowEmptyCollection()][object[]]$ConditionalAccessPolicies
    )

    $breakGlassPolicies = @($ConditionalAccessPolicies | Where-Object {
        $_.PSObject.Properties['conditions'] -and $_.conditions.PSObject.Properties['users'] -and
        (@($_.conditions.users.excludeUsers).Count -gt 0 -or @($_.conditions.users.excludeGroups).Count -gt 0)
    })
    $enabledPolicies = @($ConditionalAccessPolicies | Where-Object { $_.PSObject.Properties['state'] -and $_.state -eq 'enabled' })
    $trustedLocations = @($NamedLocations | Where-Object { $_.PSObject.Properties['isTrusted'] -and $_.isTrusted })
    $sourceIpRestoration = if ($AdaptiveAccess -and $AdaptiveAccess.PSObject.Properties['sourceIpRestorationStatus']) {
        [string]$AdaptiveAccess.sourceIpRestorationStatus
    } else { 'unknown' }
    $compliantNetwork = if ($AdaptiveAccess -and $AdaptiveAccess.PSObject.Properties['compliantNetworkStatus']) {
        [string]$AdaptiveAccess.compliantNetworkStatus
    } else { 'unknown' }
    $blockers = [System.Collections.Generic.List[string]]::new()
    if ($breakGlassPolicies.Count -eq 0) { $blockers.Add('No Conditional Access policy evidence includes excluded users or groups for emergency access review.') }
    if ($NamedLocations.Count -eq 0) { $blockers.Add('No named-location evidence was captured.') }
    if ($enabledPolicies.Count -eq 0) { $blockers.Add('No enabled Conditional Access policy evidence was captured.') }
    if ($sourceIpRestoration -eq 'unknown') { $blockers.Add('Source-IP restoration state is unknown.') }
    if ($compliantNetwork -eq 'unknown') { $blockers.Add('Compliant-network signaling state is unknown.') }
    return [pscustomobject][ordered]@{
        mutationEligible = $false
        mutationMode = 'manual-only'
        sourceIpRestorationStatus = $sourceIpRestoration
        compliantNetworkStatus = $compliantNetwork
        namedLocationCount = @($NamedLocations).Count
        trustedNamedLocationCount = $trustedLocations.Count
        enabledConditionalAccessPolicyCount = $enabledPolicies.Count
        breakGlassExclusionPolicyCount = $breakGlassPolicies.Count
        blockers = $blockers.ToArray()
        universalCae = 'platform-behavior-not-deployable'
    }
}

function Get-GsaCpePackage {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Plan)

    $link = $Plan.desired.deviceLink
    return [pscustomobject][ordered]@{
        schemaVersion = '1.0.0'
        generatedFromPlanId = $Plan.planId
        remoteNetwork = [ordered]@{ name = $Plan.desired.name; region = $Plan.desired.region }
        deviceLink = [ordered]@{
            name = $link.name
            publicIpAddress = $link.ipAddress
            bandwidthCapacityInMbps = $link.bandwidthCapacityInMbps
            bgpConfiguration = ConvertTo-GsaCanonicalValue -Value $link.bgpConfiguration
            redundancyConfiguration = ConvertTo-GsaCanonicalValue -Value $link.redundancyConfiguration
            tunnelConfiguration = ConvertTo-GsaCanonicalValue -Value $link.tunnelConfiguration
        }
        operatorInputs = @('Enter the pre-shared key interactively at execution time and configure the identical value directly on the CPE.')
        checklist = @(
            'Configure a route-based IKEv2 tunnel with any-to-any (0.0.0.0/0) traffic selectors.',
            'The CPE initiates the tunnel; Global Secure Access is the responder.',
            'Allow UDP 500/4500 and TCP 179. Enable NAT-T and DPD when NAT is present.',
            'Reverse local and peer BGP addresses on the CPE and add a static route to the Microsoft BGP peer over the tunnel.',
            'Validate MTU/MSS, advertised prefixes, route conflicts, and both Microsoft and Internet traffic profiles before forwarding production traffic.',
            'Apply all router changes manually; this package contains no executable vendor commands.'
        )
    }
}

function Test-GsaRemoteNetworkEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Plan)

    $checks = [System.Collections.Generic.List[object]]::new()
    $planClassification = if (-not $Plan.validation.valid) { 'changed' } elseif ($Plan.targetOwnership -eq 'unclaimed') { 'missing' } else { $Plan.targetOwnership }
    $checks.Add((ConvertTo-GsaReadinessCheck -Name 'Remote-network plan' -Status $(if ($Plan.validation.valid) { 'Pass' } else { 'Fail' }) `
        -Classification $planClassification -Detail "Disposition: $($Plan.disposition)." `
        -Expected 'Validated deterministic plan' -Actual $Plan.validation -ResourceKey 'remoteNetwork:plan' -Ownership $Plan.targetOwnership))
    foreach ($network in @($Plan.inventory.remoteNetworks)) {
        $risk = Get-GsaAssociationRisk -ForwardingProfiles @($network.forwardingProfiles)
        $status = if ($risk.severity -eq 'refuse') { 'Fail' } elseif ($risk.severity -eq 'warning') { 'Warning' } else { 'Info' }
        $checks.Add((ConvertTo-GsaReadinessCheck -Name "Remote network: $($network.name)" -Status $status -Classification $(if ($risk.severity -eq 'refuse') { 'changed' } else { 'reused' }) `
            -Detail $risk.detail -Expected 'Reviewed Microsoft and Internet profile associations where licensed' -Actual $network `
            -ResourceKey "remoteNetwork:$($network.id)" -Ownership $(if ($network.id -eq $Plan.targetId) { $Plan.targetOwnership } else { 'reused' })))
    }
    foreach ($deployment in @($Plan.inventory.deployments)) {
        $statusValue = [string]$deployment.status
        $known = $statusValue -in 'pending', 'inProgress', 'succeeded', 'failed', 'partiallySucceeded'
        $status = if ($statusValue -eq 'failed') { 'Fail' } elseif ($statusValue -in 'pending', 'inProgress', 'partiallySucceeded' -or -not $known) { 'Warning' } else { 'Pass' }
        $classification = if (-not $known) { 'unknownTransitional' } elseif ($statusValue -eq 'succeeded') { 'reused' } else { 'changed' }
        $checks.Add((ConvertTo-GsaReadinessCheck -Name "Network deployment: $($deployment.id)" -Status $status -Classification $classification `
            -Detail "Deployment status is '$statusValue'; errors and unknown fields were preserved." -Expected 'succeeded' -Actual $deployment))
    }
    $licenseCount = [int]$Plan.inventory.licenseCount
    $allocation = Get-GsaRemoteNetworkBandwidthAllocation -LicenseCount $licenseCount
    $checks.Add((ConvertTo-GsaReadinessCheck -Name 'Remote-network license and bandwidth indicators' -Status $(if ($licenseCount -ge 50) { 'Info' } else { 'Warning' }) `
        -Classification $(if ($licenseCount -ge 50) { 'reused' } else { 'unknownTransitional' }) `
        -Detail 'License inventory is advisory and does not prove assignment or individual entitlement.' -Expected 'At least 50 qualifying purchased licenses' `
        -Actual @{ licenseCount = $licenseCount; documentedTotalBandwidthMbps = $allocation }))
    $adaptive = $Plan.adaptiveAccessReadiness
    $checks.Add((ConvertTo-GsaReadinessCheck -Name 'Adaptive Access and compliant-network signaling' -Status $(if (@($adaptive.blockers).Count) { 'Warning' } else { 'Info' }) -Classification 'reused' `
        -Detail 'Settings and dependencies were classified read-only. Universal CAE is platform behavior, not a deployable resource; no setting was enabled or disabled.' `
        -Expected 'Break-glass exclusions, named-location dependencies, and Conditional Access review before any manual change' -Actual $adaptive `
        -ResourceKey 'networkAccess:conditionalAccessSettings' -Ownership 'reused'))
    return $checks.ToArray()
}

function ConvertTo-GsaRemoteNetworkPlanText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Plan)

    $lines = @(
        "Remote network plan: $($Plan.planId)",
        "Disposition: $($Plan.disposition)",
        "Ownership: $($Plan.targetOwnership)",
        "Cloud/API: $($Plan.azureCloud) / $($Plan.graphEnvironment) / $($Plan.apiContract)",
        "Validation errors: $(@($Plan.validation.errors).Count)",
        "Association risk: $($Plan.associationRisk.severity) - $($Plan.associationRisk.detail)",
        'No router, connector, association, Adaptive Access, named-location, Conditional Access, or Universal CAE mutation was performed.'
    )
    return $lines -join [Environment]::NewLine
}

Export-ModuleMember -Function @(
    'Assert-GsaRemoteNetworkPlanCurrent',
    'ConvertTo-GsaRemoteNetworkPlanText',
    'Get-GsaAssociationRisk',
    'Get-GsaAdaptiveAccessReadiness',
    'Get-GsaCpePackage',
    'Get-GsaRemoteNetworkBandwidthAllocation',
    'Get-GsaRemoteNetworkLicenseIndicator',
    'Get-GsaRemoteNetworkPlan',
    'Get-GsaRemoteNetworkValidation',
    'Test-GsaAsnValue',
    'Test-GsaBgpIpv4Address',
    'Test-GsaPublicIpv4Address',
    'Test-GsaRemoteNetworkEvidence',
    'Test-GsaTunnelConfiguration'
)
