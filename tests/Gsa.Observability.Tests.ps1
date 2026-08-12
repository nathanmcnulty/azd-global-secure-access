BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\scripts\modules\Gsa.Observability.psm1') -Force
    $fixturePath = Join-Path $PSScriptRoot 'fixtures'
    $inventory = Get-Content (Join-Path $fixturePath 'observability-inventory.json') -Raw | ConvertFrom-Json -Depth 50
    $clientEvidence = Get-Content (Join-Path $fixturePath 'client-readiness.json') -Raw | ConvertFrom-Json -Depth 50
    $workspaceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-monitor/providers/Microsoft.OperationalInsights/workspaces/law-existing'
}

Describe 'GSA observability planning' {
    It 'is deterministic apart from timestamps and preserves unmanaged routes' {
        $first = Get-GsaObservabilityPlan -WorkspaceResourceId $workspaceId -DiscoveredCategories $inventory.discoveredCategories `
            -ExistingSettings $inventory.existingSettings -AvailableTables $inventory.availableTables -GeneratedAt ([DateTimeOffset]'2026-08-11T00:00:00Z')
        $second = Get-GsaObservabilityPlan -WorkspaceResourceId $workspaceId -DiscoveredCategories @($inventory.discoveredCategories | Sort-Object -Descending) `
            -ExistingSettings $inventory.existingSettings -AvailableTables $inventory.availableTables -GeneratedAt ([DateTimeOffset]'2026-08-12T00:00:00Z')

        $first.planId | Should -Be $second.planId
        $first.mutationPerformed | Should -BeFalse
        ($first.categoryActions | Where-Object category -eq 'NetworkAccessTrafficLogs').disposition | Should -Be 'preserve-existing'
        ($first.categoryActions | Where-Object category -eq 'AuditLogs').existingRouteIds | Should -Contain '/providers/Microsoft.AADIAM/diagnosticSettings/security-owned'
    }

    It 'does not assume absent preview categories exist' {
        $plan = Get-GsaObservabilityPlan -WorkspaceResourceId $workspaceId -DiscoveredCategories $inventory.discoveredCategories `
            -ExistingSettings $inventory.existingSettings -AvailableTables $inventory.availableTables

        ($plan.categoryActions | Where-Object category -eq 'NetworkAccessGenerativeAIInsights').disposition | Should -Be 'unavailable'
        ($plan.categoryActions | Where-Object category -eq 'EnrichedOffice365AuditLogs').maturity | Should -Be 'preview'
    }

    It 'blocks a name collision without exact managed manifest authority' {
        $conflict = [pscustomobject]@{
            id = '/providers/Microsoft.AADIAM/diagnosticSettings/gsa-observability'
            name = 'gsa-observability'
            properties = [pscustomobject]@{ workspaceId = '/subscriptions/other/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/other'; logs = @() }
        }
        $plan = Get-GsaObservabilityPlan -WorkspaceResourceId $workspaceId -DiscoveredCategories @('RemoteNetworkHealthLogs') -ExistingSettings @($conflict)

        ($plan.categoryActions | Where-Object category -eq 'RemoteNetworkHealthLogs').disposition | Should -Be 'blocked-conflict'
        $plan.targetOwnership | Should -Be 'unmanagedConflict'
    }

    It 'requires a full existing workspace resource ID' {
        { Get-GsaObservabilityPlan -WorkspaceResourceId 'law-name' -DiscoveredCategories @() -ExistingSettings @() } | Should -Throw '*explicitly supplied existing*'
    }

    It 'generates schema-tolerant privacy-safe queries and disabled alerts' {
        $plan = Get-GsaObservabilityPlan -WorkspaceResourceId $workspaceId -DiscoveredCategories $inventory.discoveredCategories `
            -ExistingSettings $inventory.existingSettings -AvailableTables $inventory.availableTables
        $assets = Get-GsaObservabilityAsset -Plan $plan
        $queryText = ($assets.queries.Values -join "`n")

        $queryText | Should -Match 'union isfuzzy=true'
        $queryText | Should -Match 'column_ifexists'
        $assets.privacy.excludedFields | Should -Contain 'DestinationUrl'
        $assets.privacy.excludedFields | Should -Contain 'Content'
        @($assets.alerts | Where-Object enabledByDefault).Count | Should -Be 0
        $assets.prerequisites.missingTablesAreHealthy | Should -BeFalse
    }

    It 'builds a tenant deployment that preserves current target properties' {
        $manifest = [pscustomobject]@{ resources = @([pscustomobject]@{ key = 'diagnosticSetting:gsa-observability'; id = '/providers/Microsoft.AADIAM/diagnosticSettings/gsa-observability'; ownership = 'managed' }) }
        $current = [pscustomobject]@{
            id = '/providers/Microsoft.AADIAM/diagnosticSettings/gsa-observability'
            name = 'gsa-observability'
            properties = [pscustomobject]@{ workspaceId = $workspaceId; logs = @(); futureProperty = 'preserved' }
        }
        $plan = Get-GsaObservabilityPlan -WorkspaceResourceId $workspaceId -DiscoveredCategories @('RemoteNetworkHealthLogs') `
            -ExistingSettings @($current) -Manifest $manifest
        $template = Get-GsaObservabilityDeploymentTemplate -Plan $plan -CurrentSettings @($current)

        $template.resources[0].properties.futureProperty | Should -Be 'preserved'
        $template.resources[0].properties.logs[0].category | Should -Be 'RemoteNetworkHealthLogs'
        $template.resources[0].apiVersion | Should -Be '2017-04-01'
    }

    It 'rejects stale diagnostic evidence before deployment' {
        $current = Get-GsaObservabilityPlan -WorkspaceResourceId $workspaceId -DiscoveredCategories @('AuditLogs') -ExistingSettings @()
        $stale = Get-GsaObservabilityPlan -WorkspaceResourceId $workspaceId -DiscoveredCategories @('AuditLogs', 'RemoteNetworkHealthLogs') -ExistingSettings @()

        { Assert-GsaObservabilityPlanCurrent -Plan $stale -CurrentPlan $current -Manifest $null } | Should -Throw '*stale*'
    }
}

Describe 'GSA client evidence readiness' {
    It 'separates assignment evidence from endpoint health and preserves unknown values' {
        $checks = @(Test-GsaClientEvidence -Evidence $clientEvidence)

        ($checks | Where-Object name -eq 'clientAssignment').status | Should -Be 'Info'
        ($checks | Where-Object name -eq 'clientAssignment').detail | Should -Match 'does not prove installation'
        ($checks | Where-Object name -eq 'trustedRootAssignment').detail | Should -Match 'trusted-root presence'
        $future = $checks | Where-Object name -eq 'Client health evidence: FutureOS'
        $future.classification | Should -Be 'unknownTransitional'
        $future.actual['futureHealthField'] | Should -Be 'preserved'
    }

    It 'reports common conflicts without mutating endpoints' {
        $checks = @(Test-GsaClientEvidence -Evidence $clientEvidence)

        ($checks | Where-Object name -eq 'Client conflict evidence: vpn').classification | Should -Be 'changed'
        ($checks | Where-Object name -eq 'Client conflict evidence: quic').classification | Should -Be 'unknownTransitional'
        ($checks | Where-Object name -eq 'Client conflict evidence: manualProxy').detail | Should -Match 'changed no client'
    }


    It 'reports unobserved tables as inconclusive rather than healthy' {
        $plan = Get-GsaObservabilityPlan -WorkspaceResourceId $workspaceId -DiscoveredCategories @('RemoteNetworkHealthLogs') `
            -ExistingSettings @() -AvailableTables @()
        $checks = @(Test-GsaObservabilityEvidence -Plan $plan)
        $remote = $checks | Where-Object name -eq 'Diagnostic category evidence: RemoteNetworkHealthLogs'

        $remote.status | Should -Be 'Warning'
        $remote.detail | Should -Match 'inconclusive rather than healthy'
    }
}
