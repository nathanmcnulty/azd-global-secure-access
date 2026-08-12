#Requires -Version 7.0

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$JsonOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modulePath 'Gsa.Common.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.Graph.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.State.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.Readiness.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.Observability.psm1') -Force
Import-Module (Join-Path $modulePath 'Gsa.RemoteNetwork.psm1') -Force

if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    throw 'Install Microsoft.Graph.Authentication before running readiness validation.'
}

Assert-GsaPreviewGate -Feature 'Global Secure Access readiness validation' -Enabled $true

$checks = [System.Collections.Generic.List[object]]::new()
function Add-GsaCheck {
    param([Parameter(Mandatory)][object]$Check)
    $checks.Add($Check)
}

$azureCloud = Get-GsaEnvironmentValue -Name 'AZURE_CLOUD_NAME' -Default 'AzureCloud'
$graphEnvironment = Get-GsaEnvironmentValue -Name 'GSA_GRAPH_ENVIRONMENT' -Default 'Global'
$capability = Get-GsaCloudCapability -AzureCloud $azureCloud -GraphEnvironment $graphEnvironment
if (-not $capability.GraphCoreRead) {
    Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Cloud and endpoint support' -Status 'Fail' -Classification 'unsupported' `
        -Detail $capability.Evidence -Expected $capability.ExpectedGraphEnvironments -Actual @{
            azureCloud = $azureCloud
            graphEnvironment = $graphEnvironment
        })
} else {
    Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Cloud and endpoint support' -Status 'Pass' -Classification 'reused' `
        -Detail $capability.Evidence -Expected @{
            graphEnvironment = $capability.ExpectedGraphEnvironments
            armEndpoint = $capability.ArmEndpoint
        } -Actual @{
            azureCloud = $azureCloud
            graphEnvironment = $graphEnvironment
            armEndpoint = $capability.ArmEndpoint
        })
}

$manifestPath = Get-GsaStatePath
$pendingPath = Get-GsaStatePath -Pending
$manifest = Read-GsaStateManifest -Path $manifestPath
if (Test-Path -LiteralPath $pendingPath) {
    $pending = Get-Content -LiteralPath $pendingPath -Raw | ConvertFrom-Json -Depth 20
    Add-GsaCheck (Test-GsaStateTransactionReadiness -Pending $pending -Manifest $manifest)
}
if ($manifest) {
    Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'State manifest' -Status 'Pass' -Classification 'managed' `
        -Detail "Loaded schema $($manifest.schemaVersion) from '$manifestPath'." `
        -Expected 'Committed versioned manifest' -Actual @{
            schemaVersion = $manifest.schemaVersion
            desiredFingerprint = $manifest.desiredState.fingerprint
            resourceCount = @($manifest.resources).Count
        })
} else {
    Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'State manifest' -Status 'Warning' -Classification 'missing' `
        -Detail "No committed state manifest exists at '$manifestPath'. Ownership cannot be inferred from names." `
        -Expected 'Committed versioned manifest' -Actual $null)
}

$clientEvidencePath = Get-GsaEnvironmentValue -Name 'GSA_CLIENT_READINESS_EVIDENCE_PATH'
if ($clientEvidencePath) {
    if (-not (Test-Path -LiteralPath $clientEvidencePath)) {
        Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Client readiness evidence' -Status 'Fail' -Classification 'missing' `
            -Detail "Configured evidence path '$clientEvidencePath' does not exist." -Expected 'Sanitized JSON evidence file' -Actual $null)
    } else {
        $clientEvidence = Get-Content -LiteralPath $clientEvidencePath -Raw | ConvertFrom-Json -Depth 100
        foreach ($check in @(Test-GsaClientEvidence -Evidence $clientEvidence)) { Add-GsaCheck $check }
    }
} else {
    Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Client readiness evidence' -Status 'Info' -Classification 'missing' `
        -Detail 'No sanitized endpoint evidence path is configured. Intune assignment is not treated as proof of client installation, trusted-root acquisition, traffic forwarding, or health.' `
        -Expected 'Optional GSA_CLIENT_READINESS_EVIDENCE_PATH' -Actual $null)
}

$observabilityPlanPath = Get-GsaEnvironmentValue -Name 'GSA_OBSERVABILITY_PLAN_PATH'
if ($observabilityPlanPath) {
    if (-not (Test-Path -LiteralPath $observabilityPlanPath)) {
        Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Observability plan evidence' -Status 'Fail' -Classification 'missing' `
            -Detail "Configured plan path '$observabilityPlanPath' does not exist." -Expected 'Deterministic observability plan JSON' -Actual $null)
    } else {
        $observabilityPlan = Get-Content -LiteralPath $observabilityPlanPath -Raw | ConvertFrom-Json -Depth 100
        foreach ($check in @(Test-GsaObservabilityEvidence -Plan $observabilityPlan)) { Add-GsaCheck $check }
    }
} else {
    Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Observability plan evidence' -Status 'Info' -Classification 'missing' `
        -Detail 'No captured diagnostic-category, route, or table plan is configured. Category and ingestion availability remain unknown.' `
        -Expected 'Optional GSA_OBSERVABILITY_PLAN_PATH' -Actual $null)
}
$remoteNetworkPlanPath = Get-GsaEnvironmentValue -Name 'GSA_REMOTE_NETWORK_PLAN_PATH'
if ($remoteNetworkPlanPath) {
    if (-not (Test-Path -LiteralPath $remoteNetworkPlanPath)) {
        Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Remote-network plan evidence' -Status 'Fail' -Classification 'missing' `
            -Detail "Configured plan path '$remoteNetworkPlanPath' does not exist." -Expected 'Deterministic secret-free remote-network plan JSON' -Actual $null)
    } else {
        $remoteNetworkPlan = Get-Content -LiteralPath $remoteNetworkPlanPath -Raw | ConvertFrom-Json -Depth 100
        foreach ($check in @(Test-GsaRemoteNetworkEvidence -Plan $remoteNetworkPlan)) { Add-GsaCheck $check }
    }
} else {
    Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Remote-network plan evidence' -Status 'Info' -Classification 'missing' `
        -Detail 'No captured remote-network plan is configured. Remote-network, device-link, association, health, CPE, and Adaptive Access readiness remain unverified.' `
        -Expected 'Optional GSA_REMOTE_NETWORK_PLAN_PATH' -Actual $null)
}
$manifestBaselineResources = if ($manifest) {
    @($manifest.resources | Where-Object kind -in @(
        'Microsoft.Graph/networkAccess/filteringPolicy',
        'Microsoft.Graph/networkAccess/filteringProfile',
        'Microsoft.Graph/identity/conditionalAccess/policy'
    ))
} else {
    @()
}
$manifestHasInternetBaseline = $manifestBaselineResources.Count -gt 0

if (-not $capability.GraphCoreRead) {
    $graphContext = $null
} else {
    $scopes = [System.Collections.Generic.List[string]]::new()
    $scopes.Add('NetworkAccess.Read.All')
    $scopes.Add('NetworkAccessPolicy.Read.All')
    $scopes.Add('User.Read')
    $connectorGroupId = Get-GsaEnvironmentValue -Name 'GSA_CONNECTOR_GROUP_ID'
    if ($connectorGroupId) {
        # Microsoft Graph currently documents this connector-group GET surface with Directory.ReadWrite.All.
        $scopes.Add('Directory.ReadWrite.All')
    }
    if ((Get-GsaBoolean $env:GSA_ENABLE_INTERNET_BASELINE) -or $manifestHasInternetBaseline) {
        $scopes.Add('Policy.Read.All')
    }

    $graphContext = Connect-GsaGraph -Scopes @($scopes | Select-Object -Unique) -Environment $graphEnvironment
    Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Required Graph scopes' -Status 'Pass' -Classification 'reused' `
        -Detail "The current context contains all required read scopes: $($scopes -join ', ')." `
        -Expected @($scopes) -Actual @($graphContext.Scopes))

    $azureTenantId = Get-GsaEnvironmentValue -Name 'AZURE_TENANT_ID'
    if ($azureTenantId -and $graphContext.TenantId -ne $azureTenantId) {
        Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Tenant consistency' -Status 'Fail' -Classification 'unmanagedConflict' `
            -Detail "Graph tenant '$($graphContext.TenantId)' does not match Azure tenant '$azureTenantId'." `
            -Expected $azureTenantId -Actual $graphContext.TenantId)
    } else {
        Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Tenant consistency' -Status 'Pass' -Classification 'reused' `
            -Detail "Graph and Azure use tenant '$($graphContext.TenantId)'." `
            -Expected $graphContext.TenantId -Actual $graphContext.TenantId)
    }

    $tenantStatus = Get-GsaTenantStatus
    $onboardingState = [string]$tenantStatus.onboardingStatus
    $onboardingKnown = $onboardingState -in 'offboarded', 'offboardingInProgress', 'onboardingInProgress', 'onboarded', 'onboardingErrorOccurred', 'offboardingErrorOccurred'
    $onboardingClassification = if (-not $onboardingKnown) { 'unknownTransitional' } elseif ($onboardingState -eq 'onboarded') { 'reused' } else { 'changed' }
    $onboardingCheckStatus = if ($onboardingState -eq 'onboarded') { 'Pass' } elseif ($onboardingKnown) { 'Fail' } else { 'Warning' }
    Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Tenant onboarding' -Status $onboardingCheckStatus -Classification $onboardingClassification `
        -Detail "State: $onboardingState. Error: $($tenantStatus.onboardingErrorMessage)" `
        -Expected 'onboarded' -Actual $tenantStatus -ResourceKey 'networkAccess:tenantStatus')

    $forwardingProfiles = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/forwardingProfiles')
    foreach ($trafficType in 'm365', 'private', 'internet') {
        $profileMatches = @($forwardingProfiles | Where-Object { $_.trafficForwardingType -eq $trafficType })
        if ($profileMatches.Count -ne 1) {
            Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name "Forwarding profile: $trafficType" -Status 'Fail' -Classification 'missing' `
                -Detail "Expected one profile; found $($profileMatches.Count)." -Expected 1 -Actual $profileMatches.Count `
                -ResourceKey "forwardingProfile:$trafficType")
            continue
        }
        $forwardingProfile = $profileMatches[0]
        $resource = if ($manifest) {
            @($manifest.resources | Where-Object key -eq "forwardingProfile:$trafficType") | Select-Object -First 1
        } else {
            $null
        }
        $classification = if ($resource) {
            Compare-GsaResourceState -Resource $resource -Actual $forwardingProfile -ActualId $forwardingProfile.id
        } else {
            'reused'
        }
        $status = if ($classification -in 'changed', 'unmanagedConflict', 'missing') { 'Warning' } elseif ($classification -eq 'unknownTransitional') { 'Warning' } else { 'Pass' }
        Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name "Forwarding profile: $trafficType" -Status $status -Classification $classification `
            -Detail "State: $($forwardingProfile.state); object ID: $($forwardingProfile.id)." `
            -Expected $(if ($resource) { $resource.desiredState } else { 'Inventory only' }) -Actual $forwardingProfile `
            -ResourceKey "forwardingProfile:$trafficType" -Ownership $(if ($resource) { $resource.ownership } else { 'reused' }))
    }

    if ($capability.ForwardingRules) {
        $forwardingPolicies = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/forwardingPolicies')
        foreach ($policy in $forwardingPolicies) {
            $policy | Add-Member -NotePropertyName policyRules -NotePropertyValue @(
                Get-GsaGraphCollection -Uri "/beta/networkAccess/forwardingPolicies/$($policy.id)/policyRules" `
                    -Headers @{ Prefer = 'include-unknown-enum-members' }
            ) -Force
        }
        foreach ($check in @(Test-GsaMicrosoftTrafficRule -Policies $forwardingPolicies)) {
            Add-GsaCheck $check
        }
    } else {
        Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Microsoft traffic rules' -Status 'Warning' -Classification 'unsupported' `
            -Detail $capability.Evidence -Expected 'Rule-level forwarding and bypass inventory' -Actual $null)
    }

    if ($connectorGroupId) {
        $group = Invoke-MgGraphRequest -Method GET -Uri "/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$connectorGroupId" -OutputType PSObject
        $connectors = @(Get-GsaGraphCollection -Uri "/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$connectorGroupId/members")
        Add-GsaCheck (Test-GsaConnectorReadiness -Connectors $connectors -GroupName $group.name)
    } else {
        Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Private Access connector group' -Status 'Info' -Classification 'missing' `
            -Detail 'GSA_CONNECTOR_GROUP_ID is not configured.' -Expected 'Configured only when Private Access is requested' -Actual $null)
    }

    $memberships = @(Get-GsaGraphCollection -Uri '/v1.0/me/transitiveMemberOf?$select=id,displayName')
    Add-GsaCheck (Test-GsaDirectoryRoleIndicator -Memberships $memberships)

    $licenseReadScopes = @('LicenseAssignment.Read.All', 'Organization.Read.All', 'Directory.Read.All', 'Directory.ReadWrite.All')
    if (@($graphContext.Scopes | Where-Object { $_ -in $licenseReadScopes }).Count -gt 0 -and $capability.Licensing) {
        $subscribedSkus = @(Get-GsaGraphCollection -Uri '/v1.0/subscribedSkus')
        Add-GsaCheck (Test-GsaLicenseIndicator -SubscribedSkus $subscribedSkus)
    } else {
        Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'License indicators' -Status 'Warning' -Classification 'unknownTransitional' `
            -Detail 'Subscribed SKU indicators were not observable. Grant LicenseAssignment.Read.All for this advisory check; SKU data never proves user assignment or entitlement.' `
            -Expected 'Advisory tenant SKU indicators' -Actual @{ availableScopes = @($graphContext.Scopes) })
    }

    if ($capability.DeploymentLogs) {
        $deployments = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/deployments' -Headers @{ Prefer = 'include-unknown-enum-members' })
        foreach ($check in @(Test-GsaDeployment -Deployments $deployments)) {
            Add-GsaCheck $check
        }
    } else {
        Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Deployment logs' -Status 'Warning' -Classification 'unsupported' `
            -Detail 'Deployment log support is not asserted for this cloud by the current capability matrix.' `
            -Expected 'Documented deployment log API support' -Actual $capability)
    }

    if ($capability.Settings) {
        $adaptiveAccess = Invoke-MgGraphRequest -Method GET -Uri '/beta/networkAccess/settings/conditionalAccess' `
            -Headers @{ Prefer = 'include-unknown-enum-members' } -OutputType PSObject
        $signalingStatus = [string]$adaptiveAccess.signalingStatus
        $adaptiveClassification = if ($signalingStatus -in 'enabled', 'disabled') { 'reused' } else { 'unknownTransitional' }
        Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Adaptive Access / Conditional Access signaling' `
            -Status $(if ($adaptiveClassification -eq 'reused') { 'Info' } else { 'Warning' }) -Classification $adaptiveClassification `
            -Detail "Signaling status is '$signalingStatus'. The report did not change it." `
            -Expected 'Inventory only' -Actual $adaptiveAccess -ResourceKey 'networkAccess:conditionalAccessSettings')
    } else {
        Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Adaptive Access / Conditional Access signaling' -Status 'Warning' -Classification 'unsupported' `
            -Detail 'Conditional Access signaling settings support is not asserted for this cloud by the current capability matrix.' `
            -Expected 'Documented settings API support' -Actual $capability)
    }

    $manifestHasTlsCertificate = $manifest -and @(
        $manifest.resources | Where-Object kind -eq 'Microsoft.Graph/networkAccess/externalCertificateAuthorityCertificate'
    ).Count -gt 0
    if ((Get-GsaBoolean $env:GSA_ENABLE_TLS_INSPECTION) -or $manifestHasTlsCertificate) {
        if ($capability.Tls) {
            $certificates = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/tls/externalCertificateAuthorityCertificates' `
                -Headers @{ Prefer = 'include-unknown-enum-members' })
            foreach ($check in @(Test-GsaCertificateReadiness -Certificates $certificates)) {
                Add-GsaCheck $check
            }
        } else {
            Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'TLS certificate readiness' -Status 'Fail' -Classification 'unsupported' `
                -Detail $capability.Evidence -Expected 'Documented TLS certificate API support' -Actual $capability)
        }
    }

    if ((Get-GsaBoolean $env:GSA_ENABLE_INTERNET_BASELINE) -or $manifestHasInternetBaseline) {
        if ($capability.Filtering) {
            $baselineConfiguration = if ($manifestHasInternetBaseline) {
                $manifest.desiredState.configuration.internetBaseline
            } else {
                [pscustomobject]@{
                    policyName = Get-GsaEnvironmentValue -Name 'GSA_BASELINE_POLICY_NAME' -Default 'GSA POC Baseline Web Filtering'
                    blockedCategories = Get-GsaList -Value (Get-GsaEnvironmentValue -Name 'GSA_BASELINE_BLOCKED_CATEGORIES' -Default 'SocialNetworking')
                    securityProfileName = Get-GsaEnvironmentValue -Name 'GSA_BASELINE_SECURITY_PROFILE_NAME' -Default 'GSA POC Baseline Security Profile'
                    securityProfilePriority = [int](Get-GsaEnvironmentValue -Name 'GSA_BASELINE_SECURITY_PROFILE_PRIORITY' -Default '100')
                    policyLinkPriority = [int](Get-GsaEnvironmentValue -Name 'GSA_BASELINE_POLICY_LINK_PRIORITY' -Default '100')
                    conditionalAccessPolicyName = Get-GsaEnvironmentValue -Name 'GSA_BASELINE_CA_POLICY_NAME' -Default 'GSA POC Baseline Internet Access'
                }
            }
            $policyName = $baselineConfiguration.policyName
            $profileName = $baselineConfiguration.securityProfileName
            $caName = $baselineConfiguration.conditionalAccessPolicyName
            try {
                $baseline = Test-GsaInternetBaseline `
                    -Name $policyName `
                    -BlockedCategories @($baselineConfiguration.blockedCategories) `
                    -SecurityProfileName $profileName `
                    -ConditionalAccessPolicyName $caName `
                    -SecurityProfilePriority ([int]$baselineConfiguration.securityProfilePriority) `
                    -PolicyLinkPriority ([int]$baselineConfiguration.policyLinkPriority)
                $manifestPolicy = if ($manifest) {
                    @($manifest.resources | Where-Object key -eq "filteringPolicy:$policyName") | Select-Object -First 1
                } else {
                    $null
                }
                $classification = if ($manifestPolicy -and $manifestPolicy.id -ne $baseline.FilteringPolicyId) { 'unmanagedConflict' } elseif ($manifestPolicy) { 'managed' } else { 'reused' }
                Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Internet security baseline' `
                    -Status $(if ($classification -eq 'unmanagedConflict') { 'Fail' } else { 'Pass' }) -Classification $classification `
                    -Detail "Validated policy '$policyName', profile '$profileName', and disabled unassigned CA policy '$caName' without mutation." `
                    -Expected $(if ($manifestPolicy) { $manifestPolicy.id } else { 'Compatible object chain' }) -Actual $baseline)
            } catch {
                Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Internet security baseline' -Status 'Fail' -Classification 'changed' `
                    -Detail $_.Exception.Message -Expected 'Compatible object chain' -Actual $null)
            }
        } else {
            Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'Internet security baseline' -Status 'Fail' -Classification 'unsupported' `
                -Detail $capability.Evidence -Expected 'Documented filtering API support' -Actual $capability)
        }
    }

    if ($manifest) {
        $checkedKeys = @($checks.resourceKey | Where-Object { $_ })
        foreach ($resource in @($manifest.resources | Where-Object {
            (-not $_.PSObject.Properties['lifecycleState'] -or $_.lifecycleState -ne 'retired') -and
            $_.readUri -and $_.key -notin $checkedKeys
        })) {
            if ($resource.readUri -notmatch '^/(?:beta|v1\.0)/[A-Za-z0-9?&=/$_.(),%''-]+$') {
                throw "Manifest resource '$($resource.key)' contains an invalid readUri."
            }
            $actual = $null
            try {
                $actual = Invoke-MgGraphRequest -Method GET -Uri $resource.readUri `
                    -Headers @{ Prefer = 'include-unknown-enum-members' } -OutputType PSObject
            } catch {
                $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
                if ($statusCode -ne 404) {
                    throw
                }
            }
            $actualId = if ($actual -and $actual.PSObject.Properties['id']) { [string]$actual.id } else { $null }
            $classification = Compare-GsaResourceState -Resource $resource -Actual $actual -ActualId $actualId
            $status = if ($classification -in 'managed', 'reused') {
                'Pass'
            } elseif ($classification -in 'unknownTransitional', 'missing') {
                'Warning'
            } else {
                'Fail'
            }
            Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name "Manifest resource: $($resource.key)" -Status $status -Classification $classification `
                -Detail "Compared committed object ID and desired fingerprint without mutation." `
                -Expected $resource.desiredState -Actual $actual -ResourceKey $resource.key -Ownership $resource.ownership)
        }
    }
}

if ($manifest) {
    $crlResource = @($manifest.resources | Where-Object kind -eq 'Microsoft.Storage/crl') | Select-Object -First 1
    if ($crlResource) {
        $crlState = [ordered]@{
            url        = $crlResource.id
            published  = $false
            nextUpdate = $crlResource.observedState.NextUpdate
            expectedSha256 = $crlResource.observedState.Sha256
            actualSha256 = $null
            hashMatches = $false
        }
        try {
            $response = Invoke-WebRequest -Uri $crlResource.id -TimeoutSec 15
            [byte[]]$content = $response.Content
            $crlState.published = $response.StatusCode -eq 200 -and [string]$response.Headers['Content-Type'] -match '^application/pkix-crl'
            $crlState.actualSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($content))
            $crlState.hashMatches = $crlState.actualSha256 -eq $crlState.expectedSha256
        } catch {
            $crlState['error'] = $_.Exception.Message
        }
        if ($crlState.published -and -not $crlState.hashMatches) {
            Add-GsaCheck (ConvertTo-GsaReadinessCheck -Name 'CRL publication' -Status 'Fail' -Classification 'changed' `
                -Detail 'The published CRL bytes do not match the committed SHA-256 fingerprint.' `
                -Expected $crlState.expectedSha256 -Actual $crlState.actualSha256 -ResourceKey $crlResource.key -Ownership $crlResource.ownership)
        } else {
            Add-GsaCheck (Test-GsaCrlReadiness -CrlState ([pscustomobject]$crlState))
        }
    }
}

$failedChecks = @($checks | Where-Object status -eq 'Fail')
$summary = [pscustomobject][ordered]@{
    schemaVersion = '1.0.0'
    generatedAt   = [DateTimeOffset]::UtcNow.ToString('O')
    tenantId      = if ($graphContext) { $graphContext.TenantId } else { Get-GsaEnvironmentValue -Name 'AZURE_TENANT_ID' }
    environment   = [ordered]@{
        name             = Get-GsaEnvironmentValue -Name 'AZURE_ENV_NAME'
        subscriptionId   = Get-GsaEnvironmentValue -Name 'AZURE_SUBSCRIPTION_ID'
        azureCloud       = $azureCloud
        graphEnvironment = $graphEnvironment
    }
    ready         = $failedChecks.Count -eq 0
    manifest      = [ordered]@{
        path           = $manifestPath
        present        = $null -ne $manifest
        pendingPresent = Test-Path -LiteralPath $pendingPath
    }
    checks        = $checks.ToArray()
}

if ($OutputPath) {
    Write-GsaAtomicJson -Path $OutputPath -Value $summary
}
if (-not $JsonOnly) {
    foreach ($check in $summary.checks) {
        Write-Information ("[{0}] {1} ({2}) - {3}" -f $check.status, $check.name, $check.classification, $check.detail) -InformationAction Continue
    }
}
$summary | ConvertTo-Json -Depth 30

if (-not $summary.ready) {
    exit 1
}
