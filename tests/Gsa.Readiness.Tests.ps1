BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\scripts\modules\Gsa.Readiness.psm1') -Force
    $fixturePath = Join-Path $PSScriptRoot 'fixtures'
    $connectors = Get-Content (Join-Path $fixturePath 'connectors.json') -Raw | ConvertFrom-Json -Depth 20
    $certificates = Get-Content (Join-Path $fixturePath 'certificates.json') -Raw | ConvertFrom-Json -Depth 20
    $traffic = Get-Content (Join-Path $fixturePath 'microsoft-traffic.json') -Raw | ConvertFrom-Json -Depth 20
    $deployments = Get-Content (Join-Path $fixturePath 'deployments.json') -Raw | ConvertFrom-Json -Depth 20
    $skus = Get-Content (Join-Path $fixturePath 'subscribed-skus.json') -Raw | ConvertFrom-Json -Depth 20
}

Describe 'GSA readiness response contracts' {
    It 'distinguishes an uncommitted operation from a stale marker for a committed operation' {
        $pending = [pscustomobject]@{
            operationId = 'operation-id'
            startedAt = '2026-08-11T00:00:00Z'
        }
        $uncommitted = Test-GsaStateTransactionReadiness -Pending $pending -Manifest $null
        $committed = Test-GsaStateTransactionReadiness -Pending $pending -Manifest ([pscustomobject]@{
            operation = [pscustomobject]@{ id = 'operation-id'; status = 'committed' }
        })

        $uncommitted.Classification | Should -Be 'unknownTransitional'
        $uncommitted.Detail | Should -Match 'No matching ownership commit'
        $committed.Classification | Should -Be 'managed'
        $committed.Detail | Should -Match 'Ownership is committed'
    }

    It 'requires at least one active connector' {
        (Test-GsaConnectorReadiness -Connectors $connectors.active -GroupName 'Primary').Status | Should -Be 'Pass'
        $inactive = Test-GsaConnectorReadiness -Connectors $connectors.inactive -GroupName 'Primary'
        $inactive.Status | Should -Be 'Fail'
        $inactive.Classification | Should -Be 'missing'
    }

    It 'preserves unknown connector statuses instead of treating them as inactive' {
        $result = Test-GsaConnectorReadiness -Connectors $connectors.unknown -GroupName 'Primary'

        $result.Status | Should -Be 'Warning'
        $result.Classification | Should -Be 'unknownTransitional'
        $result.Actual.unknownStatuses | Should -Contain 'drainingFutureValue'
    }

    It 'reports certificate expiry and preserves unknown enum values' {
        $results = @(Test-GsaCertificateReadiness -Certificates $certificates.value -Now ([DateTimeOffset]'2026-08-11T00:00:00Z'))

        ($results | Where-Object Name -eq 'TLS certificate: Active CA').Status | Should -Be 'Pass'
        ($results | Where-Object Name -eq 'TLS certificate: Expiring CA').Classification | Should -Be 'changed'
        $future = $results | Where-Object Name -eq 'TLS certificate: Future CA'
        $future.Classification | Should -Be 'unknownTransitional'
        $future.Actual.status | Should -Be 'rotatingFutureValue'
        $future.Actual.futureStatusDetail | Should -Be 'sanitized-value'
    }

    It 'fails expired CRLs and warns before near-term expiry' {
        $expired = Test-GsaCrlReadiness -CrlState ([pscustomobject]@{
            published = $true
            nextUpdate = '2026-08-10T00:00:00Z'
        }) -Now ([DateTimeOffset]'2026-08-11T00:00:00Z')
        $near = Test-GsaCrlReadiness -CrlState ([pscustomobject]@{
            published = $true
            nextUpdate = '2026-08-15T00:00:00Z'
        }) -Now ([DateTimeOffset]'2026-08-11T00:00:00Z')

        $expired.Status | Should -Be 'Fail'
        $expired.Classification | Should -Be 'changed'
        $near.Status | Should -Be 'Warning'
    }

    It 'surfaces Microsoft traffic bypasses and unrecognized rules without overwriting them' {
        $results = @(Test-GsaMicrosoftTrafficRule -Policies $traffic.value)

        ($results | Where-Object ResourceKey -eq 'microsoftTrafficRule:rule-forward').Status | Should -Be 'Pass'
        ($results | Where-Object ResourceKey -eq 'microsoftTrafficRule:rule-bypass').Classification | Should -Be 'changed'
        $future = $results | Where-Object ResourceKey -eq 'microsoftTrafficRule:rule-future'
        $future.Classification | Should -Be 'unknownTransitional'
        $future.Actual.futureField.preserve | Should -BeTrue
    }

    It 'surfaces failed deployments and preserves future deployment stages' {
        $results = @(Test-GsaDeployment -Deployments $deployments.value)

        ($results | Where-Object Name -eq 'Deployment: deployment-failed').Status | Should -Be 'Fail'
        $future = $results | Where-Object Name -eq 'Deployment: deployment-future'
        $future.Classification | Should -Be 'unknownTransitional'
        $future.Actual.status.deploymentStage | Should -Be 'rollingBackFutureValue'
    }

    It 'keeps tenant licensing indicators advisory' {
        $withIndicator = Test-GsaLicenseIndicator -SubscribedSkus $skus.value
        $withoutIndicator = Test-GsaLicenseIndicator -SubscribedSkus @(
            [pscustomobject]@{
                skuPartNumber = 'SANITIZED_OTHER'
                capabilityStatus = 'Enabled'
                servicePlans = @()
            }
        )

        $withIndicator.Status | Should -Be 'Info'
        $withoutIndicator.Status | Should -Be 'Warning'
        $withoutIndicator.Status | Should -Not -Be 'Fail'
        $withoutIndicator.Detail | Should -Match 'cannot prove user assignment'
    }
}
