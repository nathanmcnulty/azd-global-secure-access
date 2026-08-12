Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Gsa.State.psm1') -Force

function ConvertTo-GsaReadinessCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Warning', 'Fail', 'Info')][string]$Status,
        [Parameter(Mandatory)][ValidateSet('managed', 'reused', 'missing', 'changed', 'unmanagedConflict', 'unsupported', 'unknownTransitional')][string]$Classification,
        [Parameter(Mandatory)][string]$Detail,
        [AllowNull()][object]$Expected,
        [AllowNull()][object]$Actual,
        [AllowNull()][string]$ResourceKey,
        [AllowNull()][string]$Ownership
    )

    return [pscustomobject][ordered]@{
        name           = $Name
        status         = $Status
        classification = $Classification
        detail         = $Detail
        resourceKey    = $ResourceKey
        ownership      = $Ownership
        expected       = $Expected
        actual         = $Actual
    }
}

function Test-GsaStateTransactionReadiness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Pending,
        [AllowNull()][object]$Manifest
    )

    if ($Manifest -and $Manifest.operation.id -eq $Pending.operationId -and $Manifest.operation.status -eq 'committed') {
        return ConvertTo-GsaReadinessCheck -Name 'State transaction' -Status 'Warning' -Classification 'managed' `
            -Detail "Operation '$($Pending.operationId)' committed successfully, but its pending marker was not removed. Ownership is committed; remove only the matching stale marker after review." `
            -Expected 'No stale pending marker' -Actual @{
                pending = $Pending
                committedOperation = $Manifest.operation
            }
    }
    return ConvertTo-GsaReadinessCheck -Name 'State transaction' -Status 'Warning' -Classification 'unknownTransitional' `
        -Detail "A pending operation '$($Pending.operationId)' remains from $($Pending.startedAt). No matching ownership commit exists for that operation." `
        -Expected 'No pending transaction' -Actual $Pending
}

function Test-GsaLicenseIndicator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$SubscribedSkus
    )

    $enabledSkus = @($SubscribedSkus | Where-Object capabilityStatus -eq 'Enabled')
    $servicePlans = @(
        $enabledSkus |
            ForEach-Object { @($_.servicePlans) } |
            Where-Object provisioningStatus -in 'Success', 'PendingInput' |
            ForEach-Object { [string]$_.servicePlanName } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
    $indicators = @(
        $servicePlans |
            Where-Object { $_ -match '(?i)(GLOBAL.?SECURE|NETWORK.?ACCESS|AAD_PREMIUM|ENTRA)' }
    )
    $actual = [ordered]@{
        enabledSkuPartNumbers = @($enabledSkus | ForEach-Object { $_.skuPartNumber } | Sort-Object -Unique)
        matchingServicePlans  = $indicators
    }
    if ($indicators.Count -gt 0) {
        return ConvertTo-GsaReadinessCheck -Name 'License indicators' -Status 'Info' -Classification 'reused' `
            -Detail 'Tenant-level subscribed SKU data contains possible Entra/GSA indicators. This does not prove user assignment or feature entitlement.' `
            -Expected 'Advisory only' -Actual $actual
    }
    return ConvertTo-GsaReadinessCheck -Name 'License indicators' -Status 'Warning' -Classification 'unknownTransitional' `
        -Detail 'No recognized Entra/GSA service-plan indicator was found. SKU presence is advisory and cannot prove user assignment or feature entitlement.' `
        -Expected 'Advisory only' -Actual $actual
}

function Test-GsaDirectoryRoleIndicator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Memberships
    )

    $roleNames = @(
        $Memberships |
            Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' } |
            ForEach-Object { [string]$_.displayName } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
    $supported = @('Global Reader', 'Global Secure Access Log Reader', 'Global Secure Access Administrator', 'Security Administrator')
    $matchedRoles = @($roleNames | Where-Object { $_ -in $supported })
    if ($matchedRoles.Count -gt 0) {
        return ConvertTo-GsaReadinessCheck -Name 'Directory role' -Status 'Pass' -Classification 'reused' `
            -Detail "Observed a role supported for networkAccess reads: $($matchedRoles -join ', ')." `
            -Expected $supported -Actual $roleNames
    }
    return ConvertTo-GsaReadinessCheck -Name 'Directory role' -Status 'Warning' -Classification 'unknownTransitional' `
        -Detail 'No supported networkAccess read role was observable. Custom roles and limited membership fields can make this check inconclusive.' `
        -Expected $supported -Actual $roleNames
}

function Test-GsaConnectorReadiness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Connectors,
        [AllowNull()][string]$GroupName
    )

    $statuses = @($Connectors | ForEach-Object { [string]$_.status })
    $active = @($Connectors | Where-Object status -eq 'active')
    $unknown = @($Connectors | Where-Object { $_.status -notin 'active', 'inactive' })
    $actual = [ordered]@{
        groupName       = $GroupName
        connectorCount  = $Connectors.Count
        activeCount     = $active.Count
        statusValues    = $statuses
        unknownStatuses = @($unknown | ForEach-Object { $_.status })
    }
    if ($unknown.Count -gt 0) {
        return ConvertTo-GsaReadinessCheck -Name 'Private Access connector group' -Status 'Warning' -Classification 'unknownTransitional' `
            -Detail 'Connector status includes values that are not currently recognized; exact values were preserved.' `
            -Expected 'At least one active connector' -Actual $actual
    }
    if ($active.Count -eq 0) {
        return ConvertTo-GsaReadinessCheck -Name 'Private Access connector group' -Status 'Fail' -Classification 'missing' `
            -Detail 'The configured connector group has no active connectors.' `
            -Expected 'At least one active connector' -Actual $actual
    }
    return ConvertTo-GsaReadinessCheck -Name 'Private Access connector group' -Status 'Pass' -Classification 'reused' `
        -Detail "Connector group '$GroupName' has $($active.Count) active connector(s)." `
        -Expected 'At least one active connector' -Actual $actual
}

function Test-GsaCertificateReadiness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Certificates,
        [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow
    )

    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($certificate in $Certificates) {
        $status = [string]$certificate.status
        $end = if ($certificate.PSObject.Properties['validity'] -and $certificate.validity.endDateTime) {
            [DateTimeOffset]::Parse([string]$certificate.validity.endDateTime)
        } else {
            $null
        }
        $actual = ConvertTo-GsaCanonicalValue -Value $certificate
        if ($status -notin 'csrGenerated', 'enrolling', 'active', 'expiring', 'expired', 'enabled', 'disabled') {
            $checks.Add((ConvertTo-GsaReadinessCheck -Name "TLS certificate: $($certificate.name)" -Status 'Warning' -Classification 'unknownTransitional' `
                -Detail "Certificate status '$status' is not recognized; it was preserved exactly." -Expected 'Recognized status' -Actual $actual -ResourceKey "tlsCertificate:$($certificate.id)"))
        } elseif ($status -eq 'expired' -or ($end -and $end -le $Now)) {
            $checks.Add((ConvertTo-GsaReadinessCheck -Name "TLS certificate: $($certificate.name)" -Status 'Fail' -Classification 'changed' `
                -Detail 'The TLS inspection certificate is expired.' -Expected 'Unexpired certificate' -Actual $actual -ResourceKey "tlsCertificate:$($certificate.id)"))
        } elseif ($status -eq 'expiring' -or ($end -and $end -le $Now.AddDays(90))) {
            $checks.Add((ConvertTo-GsaReadinessCheck -Name "TLS certificate: $($certificate.name)" -Status 'Warning' -Classification 'changed' `
                -Detail 'The TLS inspection certificate expires within 90 days; begin renewal.' -Expected 'More than 90 days remaining' -Actual $actual -ResourceKey "tlsCertificate:$($certificate.id)"))
        } else {
            $checks.Add((ConvertTo-GsaReadinessCheck -Name "TLS certificate: $($certificate.name)" -Status 'Pass' -Classification 'reused' `
                -Detail "Certificate status is '$status'." -Expected 'Unexpired certificate' -Actual $actual -ResourceKey "tlsCertificate:$($certificate.id)"))
        }
    }
    return $checks.ToArray()
}

function Test-GsaCrlReadiness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$CrlState,
        [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow
    )

    $nextUpdate = if ($CrlState.nextUpdate) { [DateTimeOffset]::Parse([string]$CrlState.nextUpdate) } else { $null }
    if (-not $CrlState.published) {
        return ConvertTo-GsaReadinessCheck -Name 'CRL publication' -Status 'Fail' -Classification 'missing' `
            -Detail 'The configured CRL could not be retrieved.' -Expected 'Published and unexpired CRL' -Actual $CrlState
    }
    if (-not $nextUpdate) {
        return ConvertTo-GsaReadinessCheck -Name 'CRL publication' -Status 'Warning' -Classification 'unknownTransitional' `
            -Detail 'The CRL is published, but nextUpdate is not recorded in committed state.' -Expected 'Published and unexpired CRL' -Actual $CrlState
    }
    if ($nextUpdate -le $Now) {
        return ConvertTo-GsaReadinessCheck -Name 'CRL publication' -Status 'Fail' -Classification 'changed' `
            -Detail 'The published CRL is expired.' -Expected 'Published and unexpired CRL' -Actual $CrlState
    }
    if ($nextUpdate -le $Now.AddDays(7)) {
        return ConvertTo-GsaReadinessCheck -Name 'CRL publication' -Status 'Warning' -Classification 'changed' `
            -Detail 'The published CRL expires within seven days.' -Expected 'More than seven days remaining' -Actual $CrlState
    }
    return ConvertTo-GsaReadinessCheck -Name 'CRL publication' -Status 'Pass' -Classification 'managed' `
        -Detail "The CRL is published and valid through $($nextUpdate.ToString('O'))." -Expected 'Published and unexpired CRL' -Actual $CrlState
}

function Test-GsaMicrosoftTrafficRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Policies
    )

    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($policy in $Policies | Where-Object trafficForwardingType -eq 'm365') {
        foreach ($rule in @($policy.policyRules)) {
            $action = [string]$rule.action
            $odataType = [string]$rule.'@odata.type'
            $actual = ConvertTo-GsaCanonicalValue -Value $rule
            if ($action -eq 'bypass') {
                $checks.Add((ConvertTo-GsaReadinessCheck -Name "Microsoft traffic rule: $($rule.name)" -Status 'Warning' -Classification 'changed' `
                    -Detail 'A Microsoft traffic rule has an explicit bypass override. The report did not overwrite it.' `
                    -Expected 'forward' -Actual $actual -ResourceKey "microsoftTrafficRule:$($rule.id)"))
            } elseif ($action -eq 'forward' -and $odataType -match '(?i)(m365ForwardingRule|forwardingRule)$') {
                $checks.Add((ConvertTo-GsaReadinessCheck -Name "Microsoft traffic rule: $($rule.name)" -Status 'Pass' -Classification 'reused' `
                    -Detail 'The Microsoft traffic rule forwards traffic.' -Expected 'forward' -Actual $actual -ResourceKey "microsoftTrafficRule:$($rule.id)"))
            } else {
                $checks.Add((ConvertTo-GsaReadinessCheck -Name "Microsoft traffic rule: $($rule.name)" -Status 'Warning' -Classification 'unknownTransitional' `
                    -Detail "Rule action '$action' or type '$odataType' is not recognized; the complete rule was preserved in JSON output." `
                    -Expected 'Known forwarding rule with forward or bypass action' -Actual $actual -ResourceKey "microsoftTrafficRule:$($rule.id)"))
            }
        }
    }
    if ($checks.Count -eq 0) {
        $checks.Add((ConvertTo-GsaReadinessCheck -Name 'Microsoft traffic rules' -Status 'Warning' -Classification 'missing' `
            -Detail 'No Microsoft traffic forwarding rules were returned.' -Expected 'One or more Microsoft traffic rules' -Actual @()))
    }
    return $checks.ToArray()
}

function Test-GsaDeployment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Deployments
    )

    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($deployment in $Deployments) {
        $stage = [string]$deployment.status.deploymentStage
        $actual = ConvertTo-GsaCanonicalValue -Value $deployment
        switch ($stage) {
            'failed' {
                $checks.Add((ConvertTo-GsaReadinessCheck -Name "Deployment: $($deployment.requestId)" -Status 'Fail' -Classification 'changed' `
                    -Detail "Deployment failed: $($deployment.status.message)" -Expected 'succeeded' -Actual $actual))
            }
            'succeeded' {
                $checks.Add((ConvertTo-GsaReadinessCheck -Name "Deployment: $($deployment.requestId)" -Status 'Pass' -Classification 'reused' `
                    -Detail 'Deployment succeeded.' -Expected 'succeeded' -Actual $actual))
            }
            { $_ -in 'pending', 'inProgress' } {
                $checks.Add((ConvertTo-GsaReadinessCheck -Name "Deployment: $($deployment.requestId)" -Status 'Warning' -Classification 'unknownTransitional' `
                    -Detail "Deployment remains in '$stage'." -Expected 'succeeded' -Actual $actual))
            }
            default {
                $checks.Add((ConvertTo-GsaReadinessCheck -Name "Deployment: $($deployment.requestId)" -Status 'Warning' -Classification 'unknownTransitional' `
                    -Detail "Deployment stage '$stage' is not recognized and was preserved exactly." -Expected 'Known deployment stage' -Actual $actual))
            }
        }
    }
    return $checks.ToArray()
}

Export-ModuleMember -Function @(
    'ConvertTo-GsaReadinessCheck',
    'Test-GsaCertificateReadiness',
    'Test-GsaConnectorReadiness',
    'Test-GsaCrlReadiness',
    'Test-GsaDeployment',
    'Test-GsaDirectoryRoleIndicator',
    'Test-GsaLicenseIndicator',
    'Test-GsaMicrosoftTrafficRule',
    'Test-GsaStateTransactionReadiness'
)
