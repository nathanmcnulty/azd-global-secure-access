BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $fixturePath = Join-Path $PSScriptRoot 'fixtures'
    $samplePath = Join-Path $repoRoot 'samples\azd-safe-poc.env'
    $azureYaml = Get-Content (Join-Path $repoRoot 'azure.yaml') -Raw
    $sampleText = Get-Content $samplePath -Raw
    $graphVariations = Get-Content (Join-Path $fixturePath 'graph-contract-variations.json') -Raw | ConvertFrom-Json -Depth 100
    $observabilityVariations = Get-Content (Join-Path $fixturePath 'observability-contract-variations.json') -Raw | ConvertFrom-Json -Depth 100
    $remoteVariations = Get-Content (Join-Path $fixturePath 'remote-network-contract-variations.json') -Raw | ConvertFrom-Json -Depth 100
    Import-Module (Join-Path $repoRoot 'scripts\modules\Gsa.Observability.psm1') -Force
    Import-Module (Join-Path $repoRoot 'scripts\modules\Gsa.RemoteNetwork.psm1') -Force
    $remoteDesired = Get-Content (Join-Path $fixturePath 'remote-network-desired.json') -Raw | ConvertFrom-Json -Depth 100
    $workspaceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-monitor/providers/Microsoft.OperationalInsights/workspaces/law-existing'
}

Describe 'Layer D template packaging contract' {
    It 'pins the documented template and azd versions' {
        $azureYaml | Should -Match 'azd-global-secure-access@0\.3\.0'
        $azureYaml | Should -Match 'azd:\s*">= 1\.30\.0"'
    }

    It 'ships a reference-only sample with every mutation gate disabled' {
        $sampleText | Should -Match 'Reference-only, secret-free azd values'
        $sampleText | Should -Match 'GSA_ACCEPT_GRAPH_BETA_TERMS="false"'
        $sampleText | Should -Match 'GSA_M365_PROFILE_STATE="Unchanged"'
        $sampleText | Should -Match 'GSA_INTUNE_ASSIGNMENT_MODE="None"'
        $sampleText | Should -Not -Match '(?im)^GSA_.*=("true"|"Enabled"|"AllDevices")$'
    }

    It 'keeps packaged samples and fixtures free of secret-shaped material' {
        $files = @(Get-ChildItem (Join-Path $repoRoot 'samples'), $fixturePath -Recurse -File)
        $text = ($files | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
        $text | Should -Not -Match '-----BEGIN [A-Z ]*PRIVATE KEY-----'
        $text | Should -Not -Match '(?i)bearer\s+eyJ'
        $text | Should -Not -Match '(?i)client[_-]?secret\s*[:=]\s*["'']?[^"''\s]+'
        $text | Should -Not -Match '(?i)pre.?shared.?key'
        $text | Should -Not -Match '(?i)(^|[^a-z])psk([^a-z]|$)'
    }

    It 'keeps committed azd samples outside the ignored environment state directory' {
        $samplePath | Should -Not -Match '[\\/]\.azure[\\/]'
        $trackedEnvironmentFiles = @(& git -C $repoRoot ls-files '.azure/**')
        $trackedEnvironmentFiles | Should -BeNullOrEmpty
    }
}

Describe 'Sanitized Graph contract variation fixtures' {
    It 'preserves unknown optional Graph fields and enums as fixture evidence' {
        $graphVariations.tenantStatus.unknownEnum.futureTenantField | Should -Be 'preserved'
        $graphVariations.forwardingProfiles[1].trafficForwardingType | Should -Be 'futureTrafficType'
        $graphVariations.deployments[0].status.futureStatusField | Should -Be 'preserved'
    }

    It 'contains explicit ambiguous safety-critical shapes for fail-closed tests' {
        $graphVariations.tenantStatus.ambiguous.PSObject.Properties.Name | Should -Not -Contain 'onboardingStatus'
        $graphVariations.forwardingProfiles[2].PSObject.Properties.Name | Should -Not -Contain 'id'
        $graphVariations.deployments[1].PSObject.Properties.Name | Should -Not -Contain 'status'
    }

    It 'preserves unknown client evidence without treating it as healthy' {
        $checks = @(Test-GsaClientEvidence -Evidence $observabilityVariations.clientEvidence)
        ($checks | Where-Object name -eq 'Client health evidence: FutureOS').classification | Should -Be 'unknownTransitional'
        ($checks | Where-Object name -eq 'Client conflict evidence: vpn').classification | Should -Be 'unknownTransitional'
    }

    It 'blocks an ambiguous diagnostic-setting identity instead of adopting it by name' {
        $plan = Get-GsaObservabilityPlan -WorkspaceResourceId $workspaceId -DiscoveredCategories @('RemoteNetworkHealthLogs') `
            -ExistingSettings @($observabilityVariations.settings[1])
        $plan.targetOwnership | Should -Be 'unmanagedConflict'
        ($plan.categoryActions | Where-Object category -eq 'RemoteNetworkHealthLogs').disposition | Should -Be 'blocked-conflict'
    }

    It 'preserves optional remote-network fields and refuses unknown association types' {
        $plan = Get-GsaRemoteNetworkPlan -Configuration $remoteDesired -Inventory $remoteVariations.validUnknownFields -Manifest $null
        $plan.inventory.remoteNetworks[0].futureRemoteNetworkField | Should -Be 'preserved'
        $plan.associationRisk.severity | Should -Be 'warning'
    }

    It 'fails closed when a matching remote-network identity is absent' {
        $collision = $remoteDesired | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        $collision.name = 'Sanitized Branch'
        { Get-GsaRemoteNetworkPlan -Configuration $collision -Inventory $remoteVariations.ambiguousIdentity -Manifest $null } | Should -Throw
    }

    It 'fails closed when required remote-network collections are absent' {
        { Get-GsaRemoteNetworkPlan -Configuration $remoteDesired -Inventory $remoteVariations.ambiguousCollections -Manifest $null } | Should -Throw
    }
}

Describe 'Reviewable documentation sources' {
    It 'includes every required architecture and lifecycle diagram as Mermaid source' {
        $architecture = Get-Content (Join-Path $repoRoot 'docs\architecture.md') -Raw
        ([regex]::Matches($architecture, '```mermaid')).Count | Should -BeGreaterOrEqual 6
        $architecture | Should -Match 'Ownership transaction'
        $architecture | Should -Match 'Cleanup and recovery'
        $architecture | Should -Match 'Observability and client evidence'
        $architecture | Should -Match 'Remote networks and Adaptive Access'
    }

    It 'documents deterministic release and Awesome AZD preparation without external automation' {
        Get-Content (Join-Path $repoRoot 'docs\release.md') -Raw | Should -Match 'Do not publish when validation is incomplete'
        Get-Content (Join-Path $repoRoot 'docs\awesome-azd.md') -Raw | Should -Match 'Do not submit automatically'
        Test-Path (Join-Path $repoRoot 'CHANGELOG.md') | Should -BeTrue
    }
}
