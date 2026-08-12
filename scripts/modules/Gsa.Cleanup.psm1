Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateModulePath = Join-Path $PSScriptRoot 'Gsa.State.psm1'
Import-Module $stateModulePath -Force

function Get-GsaCleanupArtifactPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('cleanup', 'forwarding-recovery')][string]$Type,
        [Parameter(Mandatory)][ValidateSet('json', 'txt')][string]$Format,
        [string]$ProjectRoot,
        [string]$EnvironmentName = $env:AZURE_ENV_NAME
    )

    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
        $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    }
    if ([string]::IsNullOrWhiteSpace($EnvironmentName)) {
        throw 'AZURE_ENV_NAME is required to resolve cleanup artifacts.'
    }
    return Join-Path (Join-Path (Join-Path $ProjectRoot '.azure') $EnvironmentName) "gsa-$Type-plan.$Format"
}

function Get-GsaObservationFingerprint {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Observations)

    return Get-GsaStateFingerprint -Value (ConvertTo-GsaCanonicalValue -Value $Observations)
}

function Get-GsaCleanupValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        return $(if ($InputObject.Contains($Name)) { $InputObject[$Name] } else { $null })
    }
    return $(if ($InputObject.PSObject.Properties[$Name]) { $InputObject.$Name } else { $null })
}

function Get-GsaForwardingObservationProjection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Observations)

    $projection = [ordered]@{}
    $entries = if ($Observations -is [System.Collections.IDictionary]) {
        @($Observations.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $Observations[$_] } })
    } else {
        @($Observations.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } })
    }
    foreach ($entry in $entries | Sort-Object Name) {
        $projection[$entry.Name] = [ordered]@{
            objectId              = [string](Get-GsaCleanupValue -InputObject $entry.Value -Name objectId)
            state                 = [string](Get-GsaCleanupValue -InputObject $entry.Value -Name state)
            trafficForwardingType = [string](Get-GsaCleanupValue -InputObject $entry.Value -Name trafficForwardingType)
        }
    }
    return $projection
}

function Get-GsaForwardingRecoveryPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Manifest,
        [Parameter(Mandatory)][object]$Observations,
        [Parameter(Mandatory)][ValidateSet('DisableForRecovery', 'RestoreCapturedState')][string]$Mode,
        [ValidateSet('m365', 'private', 'internet')][string[]]$TrafficType = @('m365', 'private', 'internet'),
        [AllowNull()][object]$RestorePlan,
        [DateTimeOffset]$GeneratedAt = [DateTimeOffset]::UtcNow,
        [ValidateRange(5, 120)][int]$ValidForMinutes = 30
    )

    $observationProjection = Get-GsaForwardingObservationProjection -Observations $Observations
    $actions = [System.Collections.Generic.List[object]]::new()
    foreach ($type in @($TrafficType | Sort-Object -Unique)) {
        if (-not $observationProjection.Contains($type)) { throw "Forwarding profile '$type' was not found." }
        $manifestResource = @($Manifest.resources | Where-Object key -eq "forwardingProfile:$type") | Select-Object -First 1
        if (-not $manifestResource -or $manifestResource.ownership -ne 'managed' -or $manifestResource.id -ne $observationProjection[$type].objectId) {
            throw "Forwarding profile '$type' is not a managed resource bound to the same exact object ID in the ownership manifest."
        }
        $desiredState = if ($Mode -eq 'DisableForRecovery') {
            'disabled'
        } else {
            if (-not $RestorePlan -or $RestorePlan.type -ne 'forwarding-recovery' -or $RestorePlan.mode -ne 'DisableForRecovery') {
                throw 'RestoreCapturedState requires the reviewed recovery plan whose captured state will be restored.'
            }
            $restoreAction = @($RestorePlan.actions | Where-Object trafficType -eq $type) | Select-Object -First 1
            if (-not $restoreAction -or $restoreAction.objectId -ne $observationProjection[$type].objectId) {
                throw "The restore source is not bound to the current exact object ID for '$type'."
            }
            [string]$restoreAction.observedState
        }
        $actions.Add([pscustomobject][ordered]@{
            trafficType   = $type
            objectId      = $observationProjection[$type].objectId
            observedState = $observationProjection[$type].state
            desiredState  = $desiredState
        })
    }
    $identity = [ordered]@{
        schemaVersion          = '1.0.0'
        type                   = 'forwarding-recovery'
        mode                   = $Mode
        sourcePlanId           = if ($RestorePlan) { [string]$RestorePlan.planId } else { $null }
        environment            = $Manifest.environment
        manifestFingerprint    = Get-GsaStateFingerprint -Value $Manifest
        observationFingerprint = Get-GsaObservationFingerprint -Observations $observationProjection
        actions                = @($actions)
    }
    return [pscustomobject][ordered]@{
        schemaVersion          = '1.0.0'
        planId                 = Get-GsaStateFingerprint -Value $identity
        type                   = 'forwarding-recovery'
        mode                   = $Mode
        sourcePlanId           = $identity.sourcePlanId
        generatedAt            = $GeneratedAt.ToUniversalTime().ToString('O')
        expiresAt              = $GeneratedAt.AddMinutes($ValidForMinutes).ToUniversalTime().ToString('O')
        environment            = ConvertTo-GsaCanonicalValue -Value $Manifest.environment
        manifestFingerprint    = $identity.manifestFingerprint
        observationFingerprint = $identity.observationFingerprint
        observations           = $observationProjection
        actions                = @($actions)
        acknowledgement        = 'Traffic forwarding changes can cause or extend an outage. Review profile scope, Microsoft traffic bypass evidence, rollback access, and the exact plan ID before execution.'
    }
}

function Get-GsaCleanupAction {
    param(
        [Parameter(Mandatory)][int]$Stage,
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][object]$Resource,
        [Parameter(Mandatory)][ValidateSet('eligible', 'blocked', 'preserve', 'manual')][string]$Disposition,
        [Parameter(Mandatory)][string]$Reason,
        [AllowNull()][object]$DesiredState,
        [string[]]$DependsOn = @()
    )

    $actionKey = '{0:D3}:{1}:{2}' -f $Stage, $Operation, $Resource.key
    return [pscustomobject][ordered]@{
        key            = $actionKey
        stage          = $Stage
        operation      = $Operation
        resourceKey    = $Resource.key
        kind           = $Resource.kind
        objectId       = $Resource.id
        ownership      = $Resource.ownership
        disposition    = $Disposition
        reason         = $Reason
        desiredState   = ConvertTo-GsaCanonicalValue -Value $DesiredState
        dependsOn      = [string[]]@($DependsOn | Sort-Object -Unique)
        graphMutation  = $Resource.kind -like 'Microsoft.Graph/*'
    }
}

function Get-GsaCleanupPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Manifest,
        [Parameter(Mandatory)][object]$Observations,
        [DateTimeOffset]$GeneratedAt = [DateTimeOffset]::UtcNow,
        [ValidateRange(1, 168)][int]$ValidForHours = 24
    )

    if (-not $Manifest.PSObject.Properties['resources'] -or -not $Manifest.PSObject.Properties['environment']) {
        throw 'Cleanup planning requires a committed GSA ownership manifest.'
    }
    $actions = [System.Collections.Generic.List[object]]::new()
    $observationMap = @{}
    if ($Observations -is [System.Collections.IDictionary]) {
        foreach ($key in $Observations.Keys) { $observationMap[[string]$key] = $Observations[$key] }
    } else {
        foreach ($property in $Observations.PSObject.Properties) { $observationMap[$property.Name] = $property.Value }
    }

    foreach ($resource in @($Manifest.resources | Sort-Object key)) {
        $observation = if ($observationMap.ContainsKey([string]$resource.key)) { $observationMap[[string]$resource.key] } else { $null }
        $actual = Get-GsaCleanupValue -InputObject $observation -Name current
        $actualId = [string](Get-GsaCleanupValue -InputObject $observation -Name objectId)
        $explicitClassification = Get-GsaCleanupValue -InputObject $observation -Name classification
        $classification = if ($explicitClassification) {
            [string]$explicitClassification
        } elseif ($actual) {
            Compare-GsaResourceState -Resource $resource -Actual $actual -ActualId $actualId
        } else {
            'unobserved'
        }

        if ($resource.ownership -ne 'managed') {
            $actions.Add((Get-GsaCleanupAction -Stage 0 -Operation 'Preserve' -Resource $resource -Disposition preserve `
                -Reason 'The ownership manifest marks this exact object ID as reused. Names and natural identifiers do not grant deletion authority.'))
            continue
        }
        if (-not $resource.id) {
            $actions.Add((Get-GsaCleanupAction -Stage 0 -Operation 'Preserve' -Resource $resource -Disposition blocked `
                -Reason 'The managed record has no exact object ID, so destructive authority cannot be established.'))
            continue
        }
        if ($classification -in 'unobserved', 'missing', 'changed', 'unmanagedConflict', 'unknownTransitional') {
            $actions.Add((Get-GsaCleanupAction -Stage 0 -Operation 'Preserve' -Resource $resource -Disposition blocked `
                -Reason "Current-state validation classified the object as '$classification'. Refresh evidence before any tenant mutation."))
            continue
        }

        switch -Wildcard ([string]$resource.kind) {
            'Microsoft.Graph/networkAccess/tenantStatus' {
                $actions.Add((Get-GsaCleanupAction -Stage 0 -Operation 'PreserveTenantOnboarding' -Resource $resource -Disposition preserve `
                    -Reason 'Tenant offboarding is not automated because the tenant-wide lifecycle is not a template-owned object operation.'))
            }
            'Microsoft.Graph/networkAccess/forwardingProfile' {
                if ($resource.previousMutableState -and $resource.previousMutableState.PSObject.Properties['state']) {
                    $actions.Add((Get-GsaCleanupAction -Stage 10 -Operation 'PlanForwardingRestore' -Resource $resource -Disposition manual `
                        -DesiredState $resource.previousMutableState -Reason 'Forwarding restoration requires a separate acknowledged recovery plan; azd down never changes profile state.'))
                } else {
                    $actions.Add((Get-GsaCleanupAction -Stage 10 -Operation 'PreserveForwardingProfile' -Resource $resource -Disposition preserve `
                        -Reason 'No prior mutable state was recorded. The system forwarding profile is preserved.'))
                }
            }
            'Microsoft.Graph/identity/conditionalAccess/policy' {
                $state = [string](Get-GsaCleanupValue -InputObject $actual -Name state)
                $disposition = if ($state -in 'disabled', 'enabledForReportingButNotEnforced') { 'eligible' } else { 'blocked' }
                $actions.Add((Get-GsaCleanupAction -Stage 20 -Operation 'VerifyConditionalAccessDisabled' -Resource $resource -Disposition $disposition `
                    -Reason $(if ($disposition -eq 'eligible') { 'The policy is non-enforcing and may proceed to later dependency checks.' } else { 'An enforcing Conditional Access policy must be disabled and observed before removal.' })))
                $actions.Add((Get-GsaCleanupAction -Stage 90 -Operation 'DeleteConditionalAccessPolicy' -Resource $resource -Disposition $disposition `
                    -DependsOn @("020:VerifyConditionalAccessDisabled:$($resource.key)") -Reason 'Deletion is limited to the exact managed object ID after non-enforcement is confirmed.'))
            }
            'Microsoft.Graph/applications' {
                $actions.Add((Get-GsaCleanupAction -Stage 30 -Operation 'RemoveManagedAssignments' -Resource $resource -Disposition manual `
                    -Reason 'Remove only assignment IDs recorded in refreshed evidence; preserve all other principals.'))
                $actions.Add((Get-GsaCleanupAction -Stage 40 -Operation 'RemoveManagedSegments' -Resource $resource -Disposition manual `
                    -DependsOn @("030:RemoveManagedAssignments:$($resource.key)") -Reason 'Remove only exact managed segment IDs after assignment evidence is refreshed.'))
                $actions.Add((Get-GsaCleanupAction -Stage 70 -Operation 'DeletePrivateApplication' -Resource $resource -Disposition manual `
                    -DependsOn @("040:RemoveManagedSegments:$($resource.key)") -Reason 'Delete the exact managed application only after assignments and segments are cleared.'))
            }
            'Microsoft.Graph/servicePrincipals' {
                $actions.Add((Get-GsaCleanupAction -Stage 60 -Operation 'DeleteServicePrincipal' -Resource $resource -Disposition manual `
                    -Reason 'Delete only the exact managed service principal after its app-role assignments are absent.'))
            }
            'Microsoft.Graph/networkAccess/filteringProfile' {
                $actions.Add((Get-GsaCleanupAction -Stage 80 -Operation 'DeleteFilteringProfile' -Resource $resource -Disposition manual `
                    -Reason 'Unlink only exact managed policy-link IDs first; unmanaged links are preserved and block deletion.'))
            }
            'Microsoft.Graph/networkAccess/filteringPolicy' {
                $actions.Add((Get-GsaCleanupAction -Stage 85 -Operation 'DeleteFilteringPolicy' -Resource $resource -Disposition manual `
                    -Reason 'Delete only after all managed links are removed and no unmanaged profile references remain.'))
            }
            'Microsoft.Graph/networkAccess/externalCertificateAuthorityCertificate' {
                $status = [string](Get-GsaCleanupValue -InputObject $actual -Name status)
                $disposition = if ($status -in 'active', 'enabled') { 'blocked' } else { 'manual' }
                $actions.Add((Get-GsaCleanupAction -Stage 100 -Operation 'RetireTlsCertificate' -Resource $resource -Disposition $disposition `
                    -Reason $(if ($disposition -eq 'blocked') { 'Active certificates are never deleted. Establish and validate replacement overlap, then retire in the Entra portal.' } else { 'Retirement remains staged and manual until traffic and replacement-certificate evidence is reviewed.' })))
            }
            'Microsoft.Graph/deviceManagement/deviceConfiguration' {
                $actions.Add((Get-GsaCleanupAction -Stage 110 -Operation 'RetireTrustedRootProfile' -Resource $resource -Disposition manual `
                    -Reason 'Retire only after every dependent TLS certificate is inactive and client trust overlap has completed.'))
            }
            'Microsoft.KeyVault/certificates' {
                $actions.Add((Get-GsaCleanupAction -Stage 120 -Operation 'RetireRootCertificate' -Resource $resource -Disposition blocked `
                    -Reason 'Root retirement requires verified replacement overlap, no active dependent GSA certificate, and CRL retention through the final certificate lifetime.'))
            }
            'Microsoft.Storage/crl' {
                $actions.Add((Get-GsaCleanupAction -Stage 130 -Operation 'RetainCrlEvidence' -Resource $resource -Disposition preserve `
                    -Reason 'The CRL remains available through the last dependent certificate validity and revocation window.'))
            }
            'Microsoft.KeyVault/vaults' {
                $actions.Add((Get-GsaCleanupAction -Stage 200 -Operation 'AzureResourceGroupCleanup' -Resource $resource -Disposition eligible `
                    -Reason 'Azure Resource Manager cleanup remains owned by azd/Bicep and is not a Microsoft Graph mutation. Purge protection remains effective.'))
            }
            'Microsoft.Storage/storageAccounts' {
                $actions.Add((Get-GsaCleanupAction -Stage 200 -Operation 'AzureResourceGroupCleanup' -Resource $resource -Disposition eligible `
                    -Reason 'Azure Resource Manager cleanup remains owned by azd/Bicep after CRL retention requirements are reviewed.'))
            }
            default {
                $actions.Add((Get-GsaCleanupAction -Stage 0 -Operation 'PreserveUnknownKind' -Resource $resource -Disposition blocked `
                    -Reason 'No reviewed cleanup handler exists for this resource kind.'))
            }
        }
    }

    $manifestFingerprint = Get-GsaStateFingerprint -Value $Manifest
    $observationFingerprint = Get-GsaObservationFingerprint -Observations $Observations
    $orderedActions = @($actions | Sort-Object stage, key)
    $identity = [ordered]@{
        schemaVersion          = '1.0.0'
        type                   = 'cleanup'
        environment            = $Manifest.environment
        manifestFingerprint    = $manifestFingerprint
        observationFingerprint = $observationFingerprint
        actions                = $orderedActions
    }
    $planId = Get-GsaStateFingerprint -Value $identity
    return [pscustomobject][ordered]@{
        schemaVersion          = '1.0.0'
        planId                 = $planId
        type                   = 'cleanup'
        mode                   = 'reportOnly'
        generatedAt            = $GeneratedAt.ToUniversalTime().ToString('O')
        expiresAt              = $GeneratedAt.AddHours($ValidForHours).ToUniversalTime().ToString('O')
        environment            = ConvertTo-GsaCanonicalValue -Value $Manifest.environment
        manifestFingerprint    = $manifestFingerprint
        observationFingerprint = $observationFingerprint
        actions                = $orderedActions
        safety                 = [ordered]@{
            graphMutationDuringAzdDown = $false
            ownershipAuthority         = 'Committed manifest exact object IDs only'
            reusedObjectsPreserved     = $true
            activeCertificatesPreserved = $true
            tenantOffboardingAutomated = $false
        }
    }
}

function ConvertTo-GsaCleanupPlanText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Plan)

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('Global Secure Access cleanup plan (report only)')
    $lines.Add("Plan ID: $($Plan.planId)")
    $lines.Add("Environment: $($Plan.environment.name)")
    $lines.Add("Generated: $($Plan.generatedAt)")
    $lines.Add("Expires: $($Plan.expiresAt)")
    $lines.Add("Manifest fingerprint: $($Plan.manifestFingerprint)")
    $lines.Add("Observation fingerprint: $($Plan.observationFingerprint)")
    $lines.Add('Microsoft Graph mutations during azd down: no')
    $lines.Add('')
    foreach ($action in @($Plan.actions | Sort-Object stage, key)) {
        $lines.Add(('[{0:D3}] {1} | {2} | {3} | {4}' -f [int]$action.stage, $action.disposition.ToUpperInvariant(), $action.operation, $action.resourceKey, $action.objectId))
        $lines.Add("  $($action.reason)")
        if (@($action.dependsOn).Count -gt 0) { $lines.Add("  Depends on: $($action.dependsOn -join ', ')") }
    }
    return ($lines -join "`n") + "`n"
}

function Write-GsaCleanupPlanArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$JsonPath,
        [Parameter(Mandatory)][string]$TextPath
    )

    Write-GsaAtomicJson -Path $JsonPath -Value $Plan
    $resolvedTextPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TextPath)
    $parent = Split-Path $resolvedTextPath -Parent
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllText($resolvedTextPath, (ConvertTo-GsaCleanupPlanText -Plan $Plan), [Text.UTF8Encoding]::new($false))
}

function Assert-GsaPlanCurrent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Manifest,
        [Parameter(Mandatory)][object]$Observations,
        [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow
    )

    if ($Now -gt [DateTimeOffset]::Parse($Plan.expiresAt)) { throw "Plan '$($Plan.planId)' has expired. Generate a fresh plan." }
    if ((Get-GsaStateFingerprint -Value $Manifest) -ne $Plan.manifestFingerprint) { throw 'The ownership manifest changed after this plan was generated.' }
    if ((Get-GsaObservationFingerprint -Observations $Observations) -ne $Plan.observationFingerprint) { throw 'Current tenant state changed after this plan was generated.' }
}

Export-ModuleMember -Function @(
    'Assert-GsaPlanCurrent',
    'ConvertTo-GsaCleanupPlanText',
    'Get-GsaCleanupArtifactPath',
    'Get-GsaForwardingObservationProjection',
    'Get-GsaObservationFingerprint',
    'Get-GsaForwardingRecoveryPlan',
    'Get-GsaCleanupPlan',
    'Write-GsaCleanupPlanArtifact'
)
