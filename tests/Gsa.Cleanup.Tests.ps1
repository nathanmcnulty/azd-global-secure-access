BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\scripts\modules\Gsa.State.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\scripts\modules\Gsa.Cleanup.psm1') -Force
    $manifest = Get-Content (Join-Path $PSScriptRoot 'fixtures\cleanup-manifest.json') -Raw | ConvertFrom-Json -Depth 100
    $observations = Get-Content (Join-Path $PSScriptRoot 'fixtures\cleanup-observations.json') -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    $generatedAt = [DateTimeOffset]::Parse('2026-08-01T12:00:00Z')
}

Describe 'Cleanup planning contract' {
    It 'produces deterministic plan IDs and text for the same semantic inputs' {
        $first = Get-GsaCleanupPlan -Manifest $manifest -Observations $observations -GeneratedAt $generatedAt
        $reordered = [ordered]@{}
        foreach ($key in @($observations.Keys | Sort-Object -Descending)) { $reordered[$key] = $observations[$key] }
        $second = Get-GsaCleanupPlan -Manifest $manifest -Observations $reordered -GeneratedAt $generatedAt

        $first.planId | Should -Be $second.planId
        (ConvertTo-GsaCleanupPlanText $first) | Should -Be (ConvertTo-GsaCleanupPlanText $second)
    }

    It 'preserves reused objects and blocks active certificate retirement' {
        $plan = Get-GsaCleanupPlan -Manifest $manifest -Observations $observations -GeneratedAt $generatedAt

        ($plan.actions | Where-Object resourceKey -eq 'connectorGroup:fixture').disposition | Should -Be 'preserve'
        ($plan.actions | Where-Object resourceKey -eq 'tlsCertificate:fixture').disposition | Should -Be 'blocked'
        ($plan.actions | Where-Object resourceKey -eq 'tlsCertificate:fixture').reason | Should -Match 'Active certificates are never deleted'
    }

    It 'orders assignments and segments before application deletion' {
        $plan = Get-GsaCleanupPlan -Manifest $manifest -Observations $observations -GeneratedAt $generatedAt
        $applicationActions = @($plan.actions | Where-Object resourceKey -eq 'privateApplication:quickaccessapp:fixture')

        ($applicationActions | Where-Object operation -eq 'RemoveManagedAssignments').stage | Should -BeLessThan ($applicationActions | Where-Object operation -eq 'RemoveManagedSegments').stage
        ($applicationActions | Where-Object operation -eq 'RemoveManagedSegments').stage | Should -BeLessThan ($applicationActions | Where-Object operation -eq 'DeletePrivateApplication').stage
    }

    It 'rejects stale manifest and current-state evidence' {
        $plan = Get-GsaCleanupPlan -Manifest $manifest -Observations $observations -GeneratedAt $generatedAt
        $changedManifest = $manifest | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        $changedManifest.operation.id = 'changed'
        $changedObservations = $observations.Clone()
        $changedObservations['forwardingProfile:internet'] = $changedObservations['forwardingProfile:internet'].Clone()
        $changedObservations['forwardingProfile:internet'].current = @{ state = 'disabled'; trafficForwardingType = 'internet' }

        { Assert-GsaPlanCurrent -Plan $plan -Manifest $changedManifest -Observations $observations -Now $generatedAt } | Should -Throw '*manifest changed*'
        { Assert-GsaPlanCurrent -Plan $plan -Manifest $manifest -Observations $changedObservations -Now $generatedAt } | Should -Throw '*tenant state changed*'
    }

    It 'builds restore actions from captured pre-recovery state rather than manifest defaults' {
        $forwarding = [ordered]@{
            internet = [ordered]@{ objectId = '00000000-0000-0000-0000-000000000010'; state = 'enabled'; trafficForwardingType = 'internet' }
        }
        $recovery = Get-GsaForwardingRecoveryPlan -Manifest $manifest -Observations $forwarding -Mode DisableForRecovery -TrafficType internet -GeneratedAt $generatedAt
        $disabled = [ordered]@{
            internet = [ordered]@{ objectId = '00000000-0000-0000-0000-000000000010'; state = 'disabled'; trafficForwardingType = 'internet' }
        }
        $restore = Get-GsaForwardingRecoveryPlan -Manifest $manifest -Observations $disabled -Mode RestoreCapturedState -TrafficType internet -RestorePlan $recovery -GeneratedAt $generatedAt

        $restore.sourcePlanId | Should -Be $recovery.planId
        $restore.actions[0].desiredState | Should -Be 'enabled'
    }

    It 'rejects forwarding recovery for a reused profile even when the object ID matches' {
        $reusedManifest = $manifest | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        ($reusedManifest.resources | Where-Object key -eq 'forwardingProfile:internet').ownership = 'reused'
        $forwarding = [ordered]@{
            internet = [ordered]@{ objectId = '00000000-0000-0000-0000-000000000010'; state = 'enabled'; trafficForwardingType = 'internet' }
        }

        { Get-GsaForwardingRecoveryPlan -Manifest $reusedManifest -Observations $forwarding -Mode DisableForRecovery -TrafficType internet -GeneratedAt $generatedAt } |
            Should -Throw '*not a managed resource*'
    }
}
