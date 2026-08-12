#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Plan')]
param(
    [Parameter(Mandatory)][string]$ConfigurationPath,
    [Parameter(Mandatory)][string]$InventoryPath,
    [string]$ManifestPath,
    [Parameter(Mandatory, ParameterSetName = 'Apply')][string]$PlanPath,
    [Parameter(Mandatory, ParameterSetName = 'Apply')][string]$AcknowledgePlanId,
    [Parameter(Mandatory, ParameterSetName = 'Apply')][SecureString]$PreSharedKey,
    [Parameter(ParameterSetName = 'Apply')][switch]$Execute,
    [string]$JsonOutputPath,
    [string]$TextOutputPath,
    [string]$CpePackageOutputPath,
    [string]$AuditOutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modulePath 'Gsa.Common.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.Graph.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.State.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.RemoteNetwork.psm1') -Force

foreach ($path in $ConfigurationPath, $InventoryPath) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required input '$path' does not exist." }
}
$configuration = Get-Content -LiteralPath $ConfigurationPath -Raw | ConvertFrom-Json -Depth 100
$inventory = Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json -Depth 100
$manifest = if ($ManifestPath) { Read-GsaStateManifest -Path $ManifestPath } else { Read-GsaStateManifest }
$azureCloud = Get-GsaEnvironmentValue -Name 'AZURE_CLOUD_NAME' -Default 'AzureCloud'
$graphEnvironment = Get-GsaEnvironmentValue -Name 'GSA_GRAPH_ENVIRONMENT' -Default 'Global'
$plan = Get-GsaRemoteNetworkPlan -Configuration $configuration -Inventory $inventory -Manifest $manifest -AzureCloud $azureCloud -GraphEnvironment $graphEnvironment
$cpePackage = Get-GsaCpePackage -Plan $plan

if ($PSCmdlet.ParameterSetName -eq 'Apply') {
    if (-not $manifest) { throw 'A committed ownership manifest is required before remote-network mutation.' }
    $reviewedPlan = Get-Content -LiteralPath $PlanPath -Raw | ConvertFrom-Json -Depth 100
    if ($AcknowledgePlanId -ne $reviewedPlan.planId) { throw 'AcknowledgePlanId must exactly match the reviewed remote-network plan ID.' }
    Assert-GsaPreviewGate -Feature 'Global Secure Access remote-network creation' -Enabled $true
    $capability = Get-GsaCloudCapability -AzureCloud $azureCloud -GraphEnvironment $graphEnvironment
    if ($azureCloud -ne 'AzureCloud' -or $graphEnvironment -ne 'Global') { throw 'Remote-network mutation is validated only for the commercial Global Microsoft Graph endpoint.' }
    Assert-GsaCloudCapability -Capability $capability -Surface GraphMutation
    $context = Connect-GsaGraph -Scopes @('NetworkAccess.ReadWrite.All', 'LicenseAssignment.Read.All') -Environment $graphEnvironment
    if ([string]$context.TenantId -ne [string]$manifest.environment.tenantId) { throw 'The Graph tenant does not match the ownership manifest.' }
    $currentNetworks = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/connectivity/remoteNetworks' -Headers @{ Prefer = 'include-unknown-enum-members' })
    foreach ($network in $currentNetworks) {
        $network | Add-Member -NotePropertyName deviceLinks -NotePropertyValue @(
            Get-GsaGraphCollection -Uri "/beta/networkAccess/connectivity/remoteNetworks/$($network.id)/deviceLinks" -Headers @{ Prefer = 'include-unknown-enum-members' }
        ) -Force
        if (-not $network.PSObject.Properties['forwardingProfiles']) { $network | Add-Member -NotePropertyName forwardingProfiles -NotePropertyValue @() }
    }
    $currentSkus = @(Get-GsaGraphCollection -Uri '/v1.0/subscribedSkus')
    $currentLicenseIndicators = Get-GsaRemoteNetworkLicenseIndicator -SubscribedSkus $currentSkus
    $currentInventory = [pscustomobject][ordered]@{
        remoteNetworks = $currentNetworks
        deployments = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/deployments' -Headers @{ Prefer = 'include-unknown-enum-members' })
        adaptiveAccess = Invoke-MgGraphRequest -Method GET -Uri '/beta/networkAccess/settings/conditionalAccess' -Headers @{ Prefer = 'include-unknown-enum-members' } -OutputType PSObject
        namedLocations = @(Get-GsaGraphCollection -Uri '/v1.0/identity/conditionalAccess/namedLocations')
        conditionalAccessPolicies = @(Get-GsaGraphCollection -Uri '/v1.0/identity/conditionalAccess/policies')
        licenseCount = $currentLicenseIndicators.conservativePurchasedSeatIndicator
        licenseIndicators = $currentLicenseIndicators
    }
    $currentPlan = Get-GsaRemoteNetworkPlan -Configuration $reviewedPlan.desired -Inventory $currentInventory -Manifest $manifest -AzureCloud $azureCloud -GraphEnvironment $graphEnvironment -GeneratedAt ([DateTimeOffset]::Parse([string]$reviewedPlan.generatedAt))
    Assert-GsaRemoteNetworkPlanCurrent -Plan $reviewedPlan -CurrentPlan $currentPlan -Manifest $manifest
    if (-not $Execute) {
        Write-Information 'Plan is current. Add -Execute with the same acknowledgement and SecureString to create the remote network and device link.' -InformationAction Continue
        return
    }
    if (-not $PSCmdlet.ShouldProcess($reviewedPlan.desired.name, 'Create the acknowledged remote network and device link without traffic-profile association')) { return }

    $desiredState = $manifest.desiredState.configuration | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable -Depth 100
    $desiredState.remoteNetwork = [ordered]@{ planId = $reviewedPlan.planId; name = $reviewedPlan.desired.name; region = $reviewedPlan.desired.region; associationMode = 'manual' }
    $transaction = Write-GsaPendingTransaction -Environment $manifest.environment -DesiredState $desiredState
    $networkBody = @{ name = $reviewedPlan.desired.name; region = $reviewedPlan.desired.region } | ConvertTo-Json -Depth 10
    $createdNetwork = Invoke-MgGraphRequest -Method POST -Uri '/beta/networkAccess/connectivity/remoteNetworks' -Body $networkBody -ContentType 'application/json' -OutputType PSObject
    if (-not $createdNetwork.id) { throw 'Graph did not return a remote-network object ID; pending state was retained.' }
    $partialAuditPath = if ($AuditOutputPath) { $AuditOutputPath } else { Join-Path (Split-Path (Get-GsaStatePath -Pending) -Parent) 'remote-network-partial.json' }
    Write-GsaAtomicJson -Path $partialAuditPath -Value ([pscustomobject][ordered]@{
        schemaVersion = '1.0.0'; operationId = $transaction.operationId; planId = $reviewedPlan.planId
        status = 'remoteNetworkCreated-deviceLinkPending'; remoteNetworkId = $createdNetwork.id
        deviceLinkId = $null; automatedRollback = $false; operatorAction = 'Inspect the remote network and pending transaction before retrying. Do not infer ownership by name.'
    })
    $linkBody = $reviewedPlan.desired.deviceLink | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable -Depth 100
    $linkBody.tunnelConfiguration['preSharedKey'] = [Net.NetworkCredential]::new('', $PreSharedKey).Password
    try {
        try {
            $createdLink = Invoke-MgGraphRequest -Method POST -Uri "/beta/networkAccess/connectivity/remoteNetworks/$($createdNetwork.id)/deviceLinks" `
                -Body ($linkBody | ConvertTo-Json -Depth 100 -Compress) -ContentType 'application/json' -OutputType PSObject
        } catch {
            throw 'Device-link creation failed. Provider error details were suppressed because they might echo the sensitive request body; pending state was retained.'
        }
    } finally {
        $linkBody.tunnelConfiguration['preSharedKey'] = $null
    }
    if (-not $createdLink.id) { throw 'Graph did not return a device-link object ID; pending state was retained for recovery.' }
    $createdLinkSafe = $createdLink | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable -Depth 100
    if ($createdLinkSafe.ContainsKey('tunnelConfiguration')) {
        [void]$createdLinkSafe.tunnelConfiguration.Remove('preSharedKey')
    }
    $remoteResource = ConvertTo-GsaStateResource -Key "remoteNetwork:$($createdNetwork.id)" -Kind 'Microsoft.Graph/networkAccess/remoteNetwork' `
        -Id $createdNetwork.id -NaturalId @{ name = $reviewedPlan.desired.name } -DesiredState $desiredState.remoteNetwork -ObservedState $createdNetwork `
        -ReadUri "/beta/networkAccess/connectivity/remoteNetworks/$($createdNetwork.id)" -Created $true -Ownership managed -Provenance created -PreviousManifest $manifest
    $linkDesired = $reviewedPlan.desired.deviceLink | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable -Depth 100
    $linkResource = ConvertTo-GsaStateResource -Key "deviceLink:$($createdLink.id)" -Kind 'Microsoft.Graph/networkAccess/deviceLink' `
        -Id $createdLink.id -NaturalId @{ remoteNetworkId = $createdNetwork.id; name = $reviewedPlan.desired.deviceLink.name } -DesiredState $linkDesired -ObservedState $createdLinkSafe `
        -ReadUri "/beta/networkAccess/connectivity/remoteNetworks/$($createdNetwork.id)/deviceLinks/$($createdLink.id)" -Created $true -Ownership managed -Provenance created -PreviousManifest $manifest
    $resources = Merge-GsaStateResourceSet -CurrentResources @($remoteResource, $linkResource) -PreviousManifest $manifest
    $committed = ConvertTo-GsaStateManifest -Environment $manifest.environment -DesiredState $desiredState -Resources $resources -OperationId $transaction.operationId
    Complete-GsaStateTransaction -Transaction $transaction -Manifest $committed
    $audit = [pscustomobject][ordered]@{
        schemaVersion = '1.0.0'; operationId = $transaction.operationId; planId = $reviewedPlan.planId; completedAt = [DateTimeOffset]::UtcNow.ToString('O')
        remoteNetworkId = $createdNetwork.id; deviceLinkId = $createdLink.id; trafficProfileAssociationsChanged = $false; routerChanged = $false; connectorChanged = $false
    }
    if ($AuditOutputPath) { Write-GsaAtomicJson -Path $AuditOutputPath -Value $audit }
    elseif (Test-Path -LiteralPath $partialAuditPath) { Write-GsaAtomicJson -Path $partialAuditPath -Value $audit }
    $audit | ConvertTo-Json -Depth 20
    return
}

$artifactRoot = Join-Path (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) '.azure') $env:AZURE_ENV_NAME) 'remote-network'
$JsonOutputPath = if ($JsonOutputPath) { $JsonOutputPath } else { Join-Path $artifactRoot 'plan.json' }
$TextOutputPath = if ($TextOutputPath) { $TextOutputPath } else { Join-Path $artifactRoot 'plan.txt' }
$CpePackageOutputPath = if ($CpePackageOutputPath) { $CpePackageOutputPath } else { Join-Path $artifactRoot 'cpe-package.json' }
Write-GsaAtomicJson -Path $JsonOutputPath -Value $plan
Write-GsaAtomicJson -Path $CpePackageOutputPath -Value $cpePackage
$resolvedText = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TextOutputPath)
$parent = Split-Path $resolvedText -Parent
if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
[IO.File]::WriteAllText($resolvedText, "$(ConvertTo-GsaRemoteNetworkPlanText -Plan $plan)`n", [Text.UTF8Encoding]::new($false))
Write-Information "Wrote secret-free remote-network plan '$JsonOutputPath' and vendor-neutral CPE package '$CpePackageOutputPath'." -InformationAction Continue
$plan | ConvertTo-Json -Depth 100
