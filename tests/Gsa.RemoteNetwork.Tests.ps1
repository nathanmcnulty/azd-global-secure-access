BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\scripts\modules\Gsa.RemoteNetwork.psm1') -Force
    $fixturePath = Join-Path $PSScriptRoot 'fixtures'
    $inventory = Get-Content (Join-Path $fixturePath 'remote-network-inventory.json') -Raw | ConvertFrom-Json -Depth 100
    $desired = Get-Content (Join-Path $fixturePath 'remote-network-desired.json') -Raw | ConvertFrom-Json -Depth 100
}

Describe 'GSA remote-network validation' {
    It 'validates documented region, public IP, BGP, ASN, bandwidth, IKE, and redundancy constraints' {
        $result = Get-GsaRemoteNetworkValidation -Configuration $desired

        $result.valid | Should -BeTrue
        $result.errors | Should -HaveCount 0
    }

    It 'rejects private CPE addresses, reserved ASNs, invalid BGP addresses, and unsupported crypto' {
        $invalid = $desired | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        $invalid.deviceLink.ipAddress = '10.0.0.10'
        $invalid.deviceLink.bgpConfiguration.localIpAddress = '127.0.0.1'
        $invalid.deviceLink.bgpConfiguration.asn = 65518
        $invalid.deviceLink.tunnelConfiguration = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.networkaccess.tunnelConfigurationIKEv2Custom'
            ipSecEncryption = 'aes256'
            ipSecIntegrity = 'sha256'
            saLifeTimeSeconds = 300
            dhGroup = 'unsupported'
            ikeEncryption = 'des'
            ikeIntegrity = 'sha1'
        }

        $result = Get-GsaRemoteNetworkValidation -Configuration $invalid
        $result.valid | Should -BeFalse
        ($result.errors -join ' ') | Should -Match 'public IPv4'
        ($result.errors -join ' ') | Should -Match 'reserved'
        ($result.errors -join ' ') | Should -Match 'IPsec'
        ($result.errors -join ' ') | Should -Match 'greater than 300'
        ($result.errors -join ' ') | Should -Match 'Diffie-Hellman'
        ($result.errors -join ' ') | Should -Match 'IKE encryption'
    }

    It 'calculates advisory license bandwidth without claiming entitlement' {
        Get-GsaRemoteNetworkBandwidthAllocation -LicenseCount 49 | Should -Be 0
        Get-GsaRemoteNetworkBandwidthAllocation -LicenseCount 75 | Should -Be 500
        Get-GsaRemoteNetworkBandwidthAllocation -LicenseCount 1000 | Should -Be 3500
        Get-GsaRemoteNetworkBandwidthAllocation -LicenseCount 10500 | Should -Be 35500
    }

    It 'uses a conservative qualifying SKU indicator without double-counting bundles' {
        $skus = @(
            [pscustomobject]@{ skuId = 'a'; skuPartNumber = 'AAD_PREMIUM'; prepaidUnits = [pscustomobject]@{ enabled = 75 }; consumedUnits = 50; servicePlans = @() },
            [pscustomobject]@{ skuId = 'b'; skuPartNumber = 'ENTRA_SUITE'; prepaidUnits = [pscustomobject]@{ enabled = 60 }; consumedUnits = 40; servicePlans = @() }
        )
        $indicator = Get-GsaRemoteNetworkLicenseIndicator -SubscribedSkus $skus

        $indicator.conservativePurchasedSeatIndicator | Should -Be 75
        $indicator.qualifyingSkus | Should -HaveCount 2
        $indicator.evidence | Should -Match 'cannot prove assignment'
    }
}

Describe 'GSA remote-network planning and evidence' {
    It 'creates deterministic plans and preserves unknown inventory fields' {
        $first = Get-GsaRemoteNetworkPlan -Configuration $desired -Inventory $inventory -Manifest $null -GeneratedAt ([DateTimeOffset]'2026-08-12T00:00:00Z')
        $second = Get-GsaRemoteNetworkPlan -Configuration $desired -Inventory $inventory -Manifest $null -GeneratedAt ([DateTimeOffset]'2026-08-12T00:05:00Z')

        $first.planId | Should -Be $second.planId
        $first.disposition | Should -Be 'eligible-create'
        $first.inventory.remoteNetworks[0]['futureRemoteNetworkField'] | Should -Be 'preserved'
        $first.inventory.deployments[0]['futureDeploymentField'] | Should -Be 'preserved'
    }

    It 'fails closed for unsupported clouds' {
        $plan = Get-GsaRemoteNetworkPlan -Configuration $desired -Inventory $inventory -Manifest $null -AzureCloud AzureUSGovernment -GraphEnvironment USGov
        $plan.disposition | Should -Be 'blocked-unsupported-cloud'
    }

    It 'does not claim an existing same-name object by name' {
        $collision = $desired | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        $collision.name = 'Existing Branch'
        $plan = Get-GsaRemoteNetworkPlan -Configuration $collision -Inventory $inventory -Manifest $null

        $plan.targetOwnership | Should -Be 'reused'
        $plan.disposition | Should -Be 'blocked-existing-unmanaged'
    }

    It 'uses exact manifest IDs for managed classification but keeps updates inventory only' {
        $managed = [pscustomobject]@{ resources = @([pscustomobject]@{ id = $inventory.remoteNetworks[0].id; kind = 'Microsoft.Graph/networkAccess/remoteNetwork'; ownership = 'managed' }) }
        $collision = $desired | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        $collision.name = 'Existing Branch'
        $plan = Get-GsaRemoteNetworkPlan -Configuration $collision -Inventory $inventory -Manifest $managed

        $plan.targetOwnership | Should -Be 'managed'
        $plan.disposition | Should -Be 'inventory-managed-no-update'
    }

    It 'refuses incomplete traffic-profile associations that can silently drop traffic' {
        $risk = Get-GsaAssociationRisk -ForwardingProfiles $inventory.remoteNetworks[0].forwardingProfiles
        $risk.severity | Should -Be 'refuse'
        $risk.detail | Should -Match 'silently drop'
    }

    It 'rejects stale current-state evidence' {
        $reviewed = Get-GsaRemoteNetworkPlan -Configuration $desired -Inventory $inventory -Manifest $null -GeneratedAt ([DateTimeOffset]'2026-08-12T00:00:00Z')
        $changedInventory = $inventory | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        $changedInventory.deployments[0].status = 'succeeded'
        $current = Get-GsaRemoteNetworkPlan -Configuration $desired -Inventory $changedInventory -Manifest $null -GeneratedAt ([DateTimeOffset]'2026-08-12T00:00:00Z')

        { Assert-GsaRemoteNetworkPlanCurrent -Plan $reviewed -CurrentPlan $current -Manifest $null -Now ([DateTimeOffset]'2026-08-12T00:10:00Z') } | Should -Throw '*stale*'
    }

    It 'rejects an expired plan even when current state is otherwise unchanged' {
        $reviewed = Get-GsaRemoteNetworkPlan -Configuration $desired -Inventory $inventory -Manifest $null -GeneratedAt ([DateTimeOffset]'2026-08-12T00:00:00Z')
        { Assert-GsaRemoteNetworkPlanCurrent -Plan $reviewed -CurrentPlan $reviewed -Manifest $null -Now ([DateTimeOffset]'2026-08-12T01:00:00Z') } | Should -Throw '*expired*'
    }

    It 'classifies duplicate names, empty associations, private profiles, and complete associations safely' {
        $duplicateInventory = $inventory | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        $duplicateInventory.remoteNetworks += ($duplicateInventory.remoteNetworks[0] | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100)
        $duplicateInventory.remoteNetworks[1].id = '22222222-2222-2222-2222-222222222222'
        $collision = $desired | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        $collision.name = 'Existing Branch'

        (Get-GsaRemoteNetworkPlan -Configuration $collision -Inventory $duplicateInventory -Manifest $null).targetOwnership | Should -Be 'unmanagedConflict'
        (Get-GsaAssociationRisk -ForwardingProfiles @()).severity | Should -Be 'warning'
        (Get-GsaAssociationRisk -ForwardingProfiles @([pscustomobject]@{ trafficForwardingType = 'private' })).severity | Should -Be 'refuse'
        (Get-GsaAssociationRisk -ForwardingProfiles @([pscustomobject]@{ trafficForwardingType = 'm365' }, [pscustomobject]@{ trafficForwardingType = 'internet' })).severity | Should -Be 'info'
    }

    It 'reports Adaptive Access blockers without making it mutation eligible' {
        $readiness = Get-GsaAdaptiveAccessReadiness -AdaptiveAccess ([pscustomobject]@{}) -NamedLocations @() -ConditionalAccessPolicies @()
        $readiness.mutationEligible | Should -BeFalse
        $readiness.mutationMode | Should -Be 'manual-only'
        $readiness.blockers | Should -Contain 'Source-IP restoration state is unknown.'
        $readiness.universalCae | Should -Be 'platform-behavior-not-deployable'
    }

    It 'generates a vendor-neutral package with no persisted secret field or value' {
        $plan = Get-GsaRemoteNetworkPlan -Configuration $desired -Inventory $inventory -Manifest $null
        $package = Get-GsaCpePackage -Plan $plan
        $text = $package | ConvertTo-Json -Depth 100

        $package.PSObject.Properties.Name | Should -Not -Contain 'preSharedKey'
        $package.deviceLink.PSObject.Properties.Name | Should -Not -Contain 'preSharedKey'
        $package.deviceLink.tunnelConfiguration.Keys | Should -Not -Contain 'preSharedKey'
        $text | Should -Not -Match 'fixture-secret|example-secret|replace-me'
        $text | Should -Match 'router changes manually'
    }

    It 'reports unknown deployment status and Adaptive Access as read-only evidence' {
        $plan = Get-GsaRemoteNetworkPlan -Configuration $desired -Inventory $inventory -Manifest $null
        $checks = @(Test-GsaRemoteNetworkEvidence -Plan $plan)

        ($checks | Where-Object name -Like 'Network deployment:*').classification | Should -Be 'unknownTransitional'
        ($checks | Where-Object name -eq 'Adaptive Access and compliant-network signaling').detail | Should -Match 'no setting was enabled or disabled'
        ($checks | Where-Object name -eq 'Remote-network license and bandwidth indicators').detail | Should -Match 'does not prove assignment'
    }
}
