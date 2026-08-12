#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Plan')]
param(
    [Parameter(ParameterSetName = 'Plan')]
    [ValidateSet('m365', 'private', 'internet')]
    [string[]]$TrafficType = @('m365', 'private', 'internet'),
    [Parameter(ParameterSetName = 'Plan')]
    [ValidateSet('DisableForRecovery', 'RestoreCapturedState')]
    [string]$Mode = 'DisableForRecovery',
    [Parameter(ParameterSetName = 'Plan')]
    [string]$RestorePlanPath,
    [Parameter(Mandatory, ParameterSetName = 'Apply')]
    [string]$PlanPath,
    [Parameter(Mandatory, ParameterSetName = 'Apply')]
    [string]$AcknowledgePlanId,
    [Parameter(Mandatory, ParameterSetName = 'Apply')]
    [switch]$AcknowledgeTrafficImpact,
    [Parameter(ParameterSetName = 'Apply')]
    [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modulePath 'Gsa.Common.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.State.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.Cleanup.psm1') -Force

Assert-GsaPreviewGate -Feature 'Global Secure Access forwarding outage recovery' -Enabled $true
$azureCloud = Get-GsaEnvironmentValue -Name 'AZURE_CLOUD_NAME' -Default 'AzureCloud'
$graphEnvironment = Get-GsaEnvironmentValue -Name 'GSA_GRAPH_ENVIRONMENT' -Default 'Global'
$capability = Get-GsaCloudCapability -AzureCloud $azureCloud -GraphEnvironment $graphEnvironment
Assert-GsaCloudCapability -Capability $capability -Surface ForwardingMutation
$manifest = Read-GsaStateManifest
if (-not $manifest) { throw 'A committed ownership manifest is required for forwarding recovery.' }
if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) { throw 'Install Microsoft.Graph.Authentication before forwarding recovery.' }
$context = Connect-GsaGraph -Scopes @('NetworkAccess.ReadWrite.All') -Environment $graphEnvironment
if ($context.TenantId -ne $manifest.environment.tenantId) { throw 'The Graph tenant does not match the ownership manifest.' }

function Get-ForwardingObservation {
    $profiles = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/forwardingProfiles')
    $result = [ordered]@{}
    foreach ($forwardingProfile in $profiles | Sort-Object trafficForwardingType) {
        $result[[string]$forwardingProfile.trafficForwardingType] = [ordered]@{
            objectId = [string]$forwardingProfile.id
            state = [string]$forwardingProfile.state
            trafficForwardingType = [string]$forwardingProfile.trafficForwardingType
        }
    }
    return $result
}

if ($PSCmdlet.ParameterSetName -eq 'Plan') {
    $observations = Get-ForwardingObservation
    $restorePlan = $null
    if ($Mode -eq 'RestoreCapturedState') {
        if ([string]::IsNullOrWhiteSpace($RestorePlanPath)) { throw 'RestorePlanPath is required for RestoreCapturedState.' }
        $restorePlan = Get-Content -LiteralPath $RestorePlanPath -Raw | ConvertFrom-Json -Depth 100
    }
    $plan = Get-GsaForwardingRecoveryPlan -Manifest $manifest -Observations $observations -Mode $Mode -TrafficType $TrafficType -RestorePlan $restorePlan
    $outputPath = Get-GsaCleanupArtifactPath -Type forwarding-recovery -Format json
    Write-GsaAtomicJson -Path $outputPath -Value $plan
    $plan | ConvertTo-Json -Depth 20
    Write-Information "Recovery plan written to '$outputPath'. No forwarding state was changed." -InformationAction Continue
    return
}

$plan = Get-Content -LiteralPath $PlanPath -Raw | ConvertFrom-Json -Depth 100
if ($plan.type -ne 'forwarding-recovery') { throw 'The supplied artifact is not a forwarding recovery plan.' }
if ($AcknowledgePlanId -ne $plan.planId) { throw 'AcknowledgePlanId must exactly match the reviewed plan ID.' }
if (-not $AcknowledgeTrafficImpact) { throw 'AcknowledgeTrafficImpact is required to validate or execute a recovery plan.' }
$observations = Get-GsaForwardingObservationProjection -Observations (Get-ForwardingObservation)
Assert-GsaPlanCurrent -Plan $plan -Manifest $manifest -Observations $observations
if (-not $Execute) {
    $plan | ConvertTo-Json -Depth 20
    Write-Information 'Plan is current. Add -Execute with the same acknowledgement to apply it.' -InformationAction Continue
    return
}

$before = $observations
foreach ($action in @($plan.actions | Sort-Object trafficType)) {
    if ($before[$action.trafficType].objectId -ne $action.objectId -or $before[$action.trafficType].state -ne $action.observedState) {
        throw "Forwarding profile '$($action.trafficType)' changed after planning."
    }
    if ($action.desiredState -eq $action.observedState) { continue }
    if ($PSCmdlet.ShouldProcess($action.objectId, "Set $($action.trafficType) forwarding state to '$($action.desiredState)'")) {
        $body = @{ state = $action.desiredState } | ConvertTo-Json -Compress
        Invoke-MgGraphRequest -Method PATCH -Uri "/beta/networkAccess/forwardingProfiles/$($action.objectId)" -Body $body -ContentType 'application/json' | Out-Null
    }
}
$after = Get-ForwardingObservation
$audit = [ordered]@{
    schemaVersion = '1.0.0'
    planId = $plan.planId
    operationId = [guid]::NewGuid().ToString()
    executedAt = [DateTimeOffset]::UtcNow.ToString('O')
    executedBy = $context.Account
    tenantId = $context.TenantId
    before = $before
    after = $after
}
$auditDirectory = Split-Path (Get-GsaCleanupArtifactPath -Type forwarding-recovery -Format json) -Parent
$auditPath = Join-Path $auditDirectory "gsa-forwarding-recovery-audit-$($audit.operationId).json"
Write-GsaAtomicJson -Path $auditPath -Value $audit
$audit | ConvertTo-Json -Depth 20
Write-Information "Recovery audit written to '$auditPath'." -InformationAction Continue
