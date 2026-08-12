BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\scripts\modules\Gsa.Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\scripts\modules\Gsa.State.psm1') -Force
}

Describe 'GSA state manifest contract' {
    It 'produces the same fingerprint for different property insertion orders' {
        $first = [ordered]@{ beta = 2; alpha = @{ second = 'b'; first = 'a' } }
        $second = [ordered]@{ alpha = @{ first = 'a'; second = 'b' }; beta = 2 }

        Get-GsaStateFingerprint $first | Should -Be (Get-GsaStateFingerprint $second)
    }

    It 'preserves single-element arrays in canonical state and JSON' {
        $canonical = ConvertTo-GsaCanonicalValue -Value @(@{ name = 'only' })
        $json = ConvertTo-Json -InputObject $canonical -Depth 10 -Compress

        $canonical.GetType().IsArray | Should -BeTrue
        $canonical | Should -HaveCount 1
        $json | Should -Be '[{"name":"only"}]'
    }

    It 'leaves an explicit pending transaction without a success-shaped manifest after partial failure' {
        $manifestPath = Join-Path $TestDrive 'gsa-state.json'
        $pendingPath = Join-Path $TestDrive 'gsa-state.pending.json'
        $environment = @{ name = 'test'; tenantId = 'tenant'; subscriptionId = 'subscription' }
        $desired = @{ forwardingProfiles = @{ m365 = $true } }

        $transaction = Write-GsaPendingTransaction -Environment $environment -DesiredState $desired -Path $pendingPath

        $transaction.status | Should -Be 'pending'
        Test-Path $pendingPath | Should -BeTrue
        Test-Path $manifestPath | Should -BeFalse
        (Get-Content $pendingPath -Raw | ConvertFrom-Json).status | Should -Be 'pending'
    }

    It 'atomically commits a valid manifest and removes the pending transaction' {
        $manifestPath = Join-Path $TestDrive 'committed-state.json'
        $pendingPath = Join-Path $TestDrive 'committed-state.pending.json'
        $environment = @{ name = 'test'; tenantId = 'tenant'; subscriptionId = 'subscription' }
        $desired = @{ forwardingProfiles = @{ m365 = $true } }
        $transaction = Write-GsaPendingTransaction -Environment $environment -DesiredState $desired -Path $pendingPath
        $resource = ConvertTo-GsaStateResource -Key 'forwardingProfile:m365' -Kind 'Microsoft.Graph/networkAccess/forwardingProfile' `
            -Id 'profile-id' -NaturalId @{ trafficForwardingType = 'm365' } `
            -DesiredState @{ state = 'enabled'; trafficForwardingType = 'm365' } `
            -ObservedState @{ state = 'enabled'; trafficForwardingType = 'm365' } `
            -PreviousMutableState @{ state = 'disabled' } -Created:$false
        $manifest = ConvertTo-GsaStateManifest -Environment $environment -DesiredState $desired -Resources @($resource) `
            -OperationId $transaction.operationId

        Complete-GsaStateTransaction -Transaction $transaction -Manifest $manifest `
            -ManifestPath $manifestPath -PendingPath $pendingPath

        Test-Path $manifestPath | Should -BeTrue
        Test-Path $pendingPath | Should -BeFalse
        Get-ChildItem $TestDrive -Filter '*.tmp' | Should -HaveCount 0
        $committed = Read-GsaStateManifest -Path $manifestPath
        $committed.operation.status | Should -Be 'committed'
        $committed.resources[0].ownership | Should -Be 'reused'
        $committed.resources[0].previousMutableState.state | Should -Be 'disabled'
    }

    It 'preserves untouched ownership and prior mutable state across later successful runs' {
        $previousResource = ConvertTo-GsaStateResource -Key 'forwardingProfile:m365' `
            -Kind 'Microsoft.Graph/networkAccess/forwardingProfile' -Id 'profile-id' `
            -NaturalId @{ trafficForwardingType = 'm365' } `
            -DesiredState @{ state = 'enabled'; trafficForwardingType = 'm365' } `
            -ObservedState @{ state = 'enabled'; trafficForwardingType = 'm365' } `
            -PreviousMutableState @{ state = 'disabled' } -Created:$true
        $previousManifest = [pscustomobject]@{ resources = @($previousResource) }
        $currentResource = ConvertTo-GsaStateResource -Key 'connectorGroup:group-id' `
            -Kind 'Microsoft.Graph/onPremisesPublishing/connectorGroup' -Id 'group-id' `
            -NaturalId @{ id = 'group-id' } -DesiredState @{ id = 'group-id' } `
            -ObservedState @{ id = 'group-id' } -Created:$false

        $merged = @(Merge-GsaStateResourceSet -CurrentResources @($currentResource) -PreviousManifest $previousManifest)

        $merged | Should -HaveCount 2
        $preserved = $merged | Where-Object key -eq 'forwardingProfile:m365'
        $preserved.ownership | Should -Be 'managed'
        $preserved.previousMutableState.state | Should -Be 'disabled'
    }

    It 'never infers ownership from a matching natural identifier or display name' {
        $prior = [pscustomobject]@{
            resources = @(
                [pscustomobject]@{
                    key = 'filteringPolicy:Baseline'
                    id = 'owned-id'
                    ownership = 'managed'
                    previousMutableState = $null
                }
            )
        }

        $sameId = ConvertTo-GsaStateResource -Key 'filteringPolicy:Baseline' -Kind 'Microsoft.Graph/networkAccess/filteringPolicy' `
            -Id 'owned-id' -NaturalId @{ name = 'Baseline' } -DesiredState @{ name = 'Baseline' } `
            -ObservedState @{ name = 'Baseline' } -Created:$false -PreviousManifest $prior
        $differentId = ConvertTo-GsaStateResource -Key 'filteringPolicy:Baseline' -Kind 'Microsoft.Graph/networkAccess/filteringPolicy' `
            -Id 'unowned-id' -NaturalId @{ name = 'Baseline' } -DesiredState @{ name = 'Baseline' } `
            -ObservedState @{ name = 'Baseline' } -Created:$false -PreviousManifest $prior

        $sameId.ownership | Should -Be 'managed'
        $differentId.ownership | Should -Be 'reused'
        $differentId.provenance | Should -Be 'reused'
        $differentId.lifecycleState | Should -Be 'active'
    }

    It 'rejects secrets, private keys, PSKs, and access tokens' {
        { Assert-GsaStateContentSafe @{ clientSecret = 'not-safe' } } | Should -Throw '*must not contain secrets*'
        { Assert-GsaStateContentSafe @{ value = '-----BEGIN PRIVATE KEY-----' } } | Should -Throw '*access token or private key*'
        { Assert-GsaStateContentSafe @{ psk = 'not-safe' } } | Should -Throw '*must not contain secrets*'
    }

    It 'preserves unknown status values while classifying them as transitional' {
        $resource = ConvertTo-GsaStateResource -Key 'tlsCertificate:id' -Kind 'Microsoft.Graph/networkAccess/externalCertificateAuthorityCertificate' `
            -Id 'id' -NaturalId @{ name = 'CA' } -DesiredState @{ status = 'active' } `
            -ObservedState @{ status = 'active' } -Created:$true
        $actual = [pscustomobject]@{ id = 'id'; status = 'rotatingFutureValue'; futureField = 'preserved' }

        Compare-GsaResourceState -Resource $resource -Actual $actual -ActualId $actual.id | Should -Be 'unknownTransitional'
        $actual.status | Should -Be 'rotatingFutureValue'
        $actual.futureField | Should -Be 'preserved'
    }

    It 'compares array objects by desired fields without treating unknown Graph fields as drift' {
        $desired = @{
            action = 'block'
            policyRules = @(
                @{
                    ruleType = 'webCategory'
                    destinations = @(
                        @{ name = 'ArtificialIntelligence' },
                        @{ name = 'SocialNetworking' }
                    )
                }
            )
        }
        $resource = ConvertTo-GsaStateResource -Key 'filteringPolicy:Baseline' -Kind 'Microsoft.Graph/networkAccess/filteringPolicy' `
            -Id 'policy-id' -NaturalId @{ name = 'Baseline' } -DesiredState $desired -ObservedState $desired -Created:$true
        $actual = [pscustomobject]@{
            id = 'policy-id'
            action = 'block'
            policyRules = @(
                [pscustomobject]@{
                    '@odata.type' = '#microsoft.graph.networkaccess.webCategoryFilteringRule'
                    ruleType = 'webCategory'
                    destinations = @(
                        [pscustomobject]@{ name = 'SocialNetworking'; futureField = 'preserved' },
                        [pscustomobject]@{ name = 'ArtificialIntelligence'; futureField = 'preserved' }
                    )
                }
            )
        }

        Compare-GsaResourceState -Resource $resource -Actual $actual -ActualId $actual.id | Should -Be 'managed'
    }

    It 'uses an application desired shape that is returned by its Graph read' {
        $desired = [ordered]@{
            appId = 'application-id'
            displayName = 'GSA Quick Access'
            onPremisesPublishing = [ordered]@{
                applicationType = 'quickaccessapp'
                isAccessibleViaZTNAClient = $true
            }
        }
        $resource = ConvertTo-GsaStateResource -Key 'privateApplication:quickaccessapp:application-id' `
            -Kind 'Microsoft.Graph/applications' -Id 'object-id' -NaturalId @{ appId = 'application-id' } `
            -DesiredState $desired -ObservedState $desired -Created:$true
        $actual = [pscustomobject]@{
            id = 'object-id'
            appId = 'application-id'
            displayName = 'GSA Quick Access'
            onPremisesPublishing = [pscustomobject]@{
                applicationType = 'quickaccessapp'
                isAccessibleViaZTNAClient = $true
                futureProperty = 'preserved'
            }
        }

        Compare-GsaResourceState -Resource $resource -Actual $actual -ActualId $actual.id | Should -Be 'managed'
    }
}

Describe 'GSA cloud capability contract' {
    It 'supports US Government forwarding reads without claiming TLS or mutation support' {
        $capability = Get-GsaCloudCapability -AzureCloud AzureUSGovernment -GraphEnvironment USGov

        $capability.ForwardingRules | Should -BeTrue
        $capability.Tls | Should -BeFalse
        $capability.GraphMutation | Should -BeFalse
        { Assert-GsaCloudCapability -Capability $capability -Surface Tls } | Should -Throw '*unsupported*'
    }

    It 'fails closed for networkAccess in Azure China' {
        $capability = Get-GsaCloudCapability -AzureCloud AzureChinaCloud -GraphEnvironment China

        $capability.Licensing | Should -BeTrue
        $capability.GraphCoreRead | Should -BeFalse
        { Assert-GsaCloudCapability -Capability $capability -Surface GraphCoreRead } | Should -Throw '*unsupported*'
    }
}
