#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Plan')]
param(
    [Parameter(Mandatory)][string]$InventoryPath,
    [string]$WorkspaceResourceId = $env:GSA_LOG_ANALYTICS_WORKSPACE_ID,
    [string]$ManifestPath,
    [Parameter(Mandatory, ParameterSetName = 'Apply')][string]$PlanPath,
    [Parameter(Mandatory, ParameterSetName = 'Apply')][string]$AcknowledgePlanId,
    [Parameter(Mandatory, ParameterSetName = 'Apply')][string]$DeploymentLocation,
    [Parameter(ParameterSetName = 'Apply')][switch]$Execute,
    [string]$JsonOutputPath,
    [string]$TextOutputPath,
    [string]$AssetsOutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modulePath 'Gsa.State.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.Observability.psm1') -Force

if (-not (Test-Path -LiteralPath $InventoryPath)) {
    throw "Observability inventory '$InventoryPath' does not exist. Capture read-only category, setting, and table evidence before planning."
}
if ([string]::IsNullOrWhiteSpace($WorkspaceResourceId)) {
    throw 'GSA_LOG_ANALYTICS_WORKSPACE_ID or WorkspaceResourceId must identify an existing workspace. This template does not create one.'
}

$inventory = Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json -Depth 100
$manifest = if ($ManifestPath) { Read-GsaStateManifest -Path $ManifestPath } else { Read-GsaStateManifest }
$plan = Get-GsaObservabilityPlan -WorkspaceResourceId $WorkspaceResourceId `
    -DiscoveredCategories @($inventory.discoveredCategories) -ExistingSettings @($inventory.existingSettings) `
    -AvailableTables @($inventory.availableTables) -Manifest $manifest
$assets = Get-GsaObservabilityAsset -Plan $plan

if ($PSCmdlet.ParameterSetName -eq 'Apply') {
    if (-not $manifest) { throw 'A committed ownership manifest is required before tenant diagnostic-setting mutation.' }
    $reviewedPlan = Get-Content -LiteralPath $PlanPath -Raw | ConvertFrom-Json -Depth 100
    if ($AcknowledgePlanId -ne $reviewedPlan.planId) { throw 'AcknowledgePlanId must exactly match the reviewed observability plan ID.' }
    $account = & az account show --output json --only-show-errors | ConvertFrom-Json -Depth 20
    if ($LASTEXITCODE -ne 0) { throw 'Unable to read the current Azure account context.' }
    if ([string]$account.tenantId -ne [string]$manifest.environment.tenantId) { throw 'The Azure tenant does not match the ownership manifest.' }
    $categoryResponse = & az rest --method get --url 'https://management.azure.com/providers/Microsoft.AADIAM/diagnosticSettingsCategories?api-version=2017-04-01-preview' --output json --only-show-errors | ConvertFrom-Json -Depth 100
    if ($LASTEXITCODE -ne 0) { throw 'Unable to discover the tenant diagnostic categories.' }
    $settingResponse = & az rest --method get --url 'https://management.azure.com/providers/Microsoft.AADIAM/diagnosticSettings?api-version=2017-04-01-preview' --output json --only-show-errors | ConvertFrom-Json -Depth 100
    if ($LASTEXITCODE -ne 0) { throw 'Unable to read the current tenant diagnostic settings.' }
    $plan = Get-GsaObservabilityPlan -WorkspaceResourceId $reviewedPlan.inventory.workspaceResourceId `
        -SettingName $reviewedPlan.settingName -RequestedCategories @($reviewedPlan.categoryActions.category) `
        -DiscoveredCategories @($categoryResponse.value | ForEach-Object name) -ExistingSettings @($settingResponse.value) `
        -AvailableTables @($reviewedPlan.inventory.availableTables) -Manifest $manifest
    Assert-GsaObservabilityPlanCurrent -Plan $reviewedPlan -CurrentPlan $plan -Manifest $manifest
    $template = Get-GsaObservabilityDeploymentTemplate -Plan $reviewedPlan -CurrentSettings @($settingResponse.value)
    $templatePath = Join-Path (Split-Path (Get-GsaObservabilityArtifactPath -Type plan-json) -Parent) 'gsa-observability-deployment.json'
    Write-GsaAtomicJson -Path $templatePath -Value $template
    if (-not $Execute) {
        Write-Information "Plan is current and deployment source was written to '$templatePath'. Add -Execute with the same acknowledgement to deploy." -InformationAction Continue
        $template | ConvertTo-Json -Depth 100
        return
    }

    if (-not $PSCmdlet.ShouldProcess($reviewedPlan.targetId, 'Deploy the acknowledged tenant diagnostic setting to the existing workspace')) {
        return
    }
    $desiredState = $manifest.desiredState.configuration | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable -Depth 100
    $desiredState.observability = [ordered]@{
        settingName = $reviewedPlan.settingName
        workspaceResourceId = $reviewedPlan.inventory.workspaceResourceId
        categories = @($reviewedPlan.categoryActions | Where-Object disposition -in 'eligible-create', 'eligible-update' | ForEach-Object category | Sort-Object -Unique)
        planId = $reviewedPlan.planId
    }
    $transaction = Write-GsaPendingTransaction -Environment $manifest.environment -DesiredState $desiredState
    & az deployment tenant create --name "gsa-observability-$($transaction.operationId)" --location $DeploymentLocation --template-file $templatePath --only-show-errors | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The tenant diagnostic-setting deployment failed; the pending state transaction was retained.' }
    $resource = ConvertTo-GsaStateResource -Key "diagnosticSetting:$($reviewedPlan.settingName)" -Kind 'Microsoft.AADIAM/diagnosticSettings' `
        -Id $reviewedPlan.targetId -NaturalId @{ name = $reviewedPlan.settingName } -DesiredState $desiredState.observability `
        -ObservedState $desiredState.observability -ReadUri $reviewedPlan.targetId -Created ($reviewedPlan.targetOwnership -eq 'unclaimed') `
        -Ownership managed -Provenance $(if ($reviewedPlan.targetOwnership -eq 'unclaimed') { 'created' } else { 'declared' }) `
        -PreviousManifest $manifest
    $resources = Merge-GsaStateResourceSet -CurrentResources @($resource) -PreviousManifest $manifest
    $committed = ConvertTo-GsaStateManifest -Environment $manifest.environment -DesiredState $desiredState -Resources $resources -OperationId $transaction.operationId
    Complete-GsaStateTransaction -Transaction $transaction -Manifest $committed
    Write-Information "Committed managed diagnostic setting '$($reviewedPlan.targetId)' after the acknowledged deployment." -InformationAction Continue
    return
}

$JsonOutputPath = if ($JsonOutputPath) { $JsonOutputPath } else { Get-GsaObservabilityArtifactPath -Type plan-json }
$TextOutputPath = if ($TextOutputPath) { $TextOutputPath } else { Get-GsaObservabilityArtifactPath -Type plan-text }
$AssetsOutputPath = if ($AssetsOutputPath) { $AssetsOutputPath } else { Get-GsaObservabilityArtifactPath -Type assets-json }

Write-GsaAtomicJson -Path $JsonOutputPath -Value $plan
Write-GsaAtomicJson -Path $AssetsOutputPath -Value $assets
$resolvedText = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TextOutputPath)
$parent = Split-Path $resolvedText -Parent
if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
[IO.File]::WriteAllText($resolvedText, "$(ConvertTo-GsaObservabilityPlanText -Plan $plan)`n", [Text.UTF8Encoding]::new($false))

Write-Information "Wrote non-mutating observability plan '$JsonOutputPath', text plan '$TextOutputPath', and gated assets '$AssetsOutputPath'." -InformationAction Continue
$plan | ConvertTo-Json -Depth 100
