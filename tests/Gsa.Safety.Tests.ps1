BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $allPowerShell = Get-ChildItem (Join-Path $repoRoot 'scripts') -Recurse -Include *.ps1, *.psm1
    $scriptText = ($allPowerShell | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
    $bicepText = (Get-ChildItem (Join-Path $repoRoot 'infra') -Recurse -Filter *.bicep | ForEach-Object {
        Get-Content $_.FullName -Raw
    }) -join "`n"
    $postProvisionText = Get-Content (Join-Path $repoRoot 'scripts\Invoke-PostProvision.ps1') -Raw
    $preProvisionText = Get-Content (Join-Path $repoRoot 'scripts\Invoke-PreProvision.ps1') -Raw
    $readinessText = Get-Content (Join-Path $repoRoot 'scripts\Test-GsaReadiness.ps1') -Raw
    $preDownText = Get-Content (Join-Path $repoRoot 'scripts\Invoke-PreDown.ps1') -Raw
    $cleanupText = Get-Content (Join-Path $repoRoot 'scripts\modules\Gsa.Cleanup.psm1') -Raw
    $recoveryText = Get-Content (Join-Path $repoRoot 'scripts\Invoke-GsaForwardingRecovery.ps1') -Raw
    $stateText = Get-Content (Join-Path $repoRoot 'scripts\modules\Gsa.State.psm1') -Raw
    $commonText = Get-Content (Join-Path $repoRoot 'scripts\modules\Gsa.Common.psm1') -Raw
    $certificateText = Get-Content (Join-Path $repoRoot 'scripts\modules\Gsa.Certificate.psm1') -Raw
    $intuneText = Get-Content (Join-Path $repoRoot 'scripts\modules\Gsa.Intune.psm1') -Raw
    $azureYamlText = Get-Content (Join-Path $repoRoot 'azure.yaml') -Raw
    $observabilityText = Get-Content (Join-Path $repoRoot 'scripts\modules\Gsa.Observability.psm1') -Raw
    $observabilityPlanText = Get-Content (Join-Path $repoRoot 'scripts\New-GsaObservabilityPlan.ps1') -Raw
    $remoteNetworkText = Get-Content (Join-Path $repoRoot 'scripts\modules\Gsa.RemoteNetwork.psm1') -Raw
    $remoteNetworkPlanText = Get-Content (Join-Path $repoRoot 'scripts\New-GsaRemoteNetworkPlan.ps1') -Raw
    $remoteNetworkInventoryText = Get-Content (Join-Path $repoRoot 'scripts\Get-GsaRemoteNetworkInventory.ps1') -Raw
}

Describe 'PowerShell syntax' {
    It 'parses every script and module' {
        foreach ($file in $allPowerShell) {
            $tokens = $null
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
            $errors | Should -HaveCount 0 -Because $file.FullName
        }
    }
}

Describe 'Azure infrastructure safety contract' {
    It 'uses Premium RBAC Key Vault with purge protection' {
        $bicepText | Should -Match "name:\s*'premium'"
        $bicepText | Should -Match 'enableRbacAuthorization:\s*true'
        $bicepText | Should -Match 'enablePurgeProtection:\s*true'
        $bicepText | Should -Match 'softDeleteRetentionInDays:\s*90'
    }

    It 'disables Storage Shared Key and anonymous blob access' {
        $bicepText | Should -Match 'allowSharedKeyAccess:\s*false'
        $bicepText | Should -Match 'allowBlobPublicAccess:\s*false'
        $bicepText | Should -Match 'defaultToOAuthAuthentication:\s*true'
        $scriptText | Should -Not -Match 'listKeys|SharedKey\s+\$\{'
    }

    It 'permits HTTP only for the deliberate signed CRL endpoint' {
        $bicepText | Should -Match 'supportsHttpsTrafficOnly:\s*false'
        $bicepText | Should -Match "minimumTlsVersion:\s*'TLS1_2'"
    }

    It 'uses deterministic role assignments' {
        $bicepText | Should -Match 'name:\s*guid\(vault\.id,\s*principalId,\s*certificatesOfficerRoleId\)'
        $bicepText | Should -Match 'name:\s*guid\(storage\.id,\s*principalId,\s*blobDataOwnerRoleId\)'
        $bicepText | Should -Match 'name:\s*guid\(storage\.id,\s*principalId,\s*storageAccountContributorRoleId\)'
    }
}

Describe 'Certificate lifecycle safety contract' {
    It 'creates a non-exportable RSA-HSM 4096 root' {
        $certificateText | Should -Match "exportable\s*=\s*\`$false"
        $certificateText | Should -Match "kty\s*=\s*'RSA-HSM'"
        $certificateText | Should -Match 'key_size\s*=\s*4096'
    }

    It 'uses the required subordinate CA constraints' {
        $certificateText | Should -Match 'X509BasicConstraintsExtension\]::new\(\$true,\s*\$true,\s*1,\s*\$true\)'
        $certificateText | Should -Match "'1\.3\.6\.1\.5\.5\.7\.3\.1'"
        $certificateText | Should -Match 'CrlSign'
    }

    It 'publishes and verifies the CRL before creating a Graph certificate' {
        $postProvisionText.IndexOf('Publish-GsaCrl') | Should -BeLessThan $postProvisionText.IndexOf('Set-GsaTlsCertificate')
        $certificateText | Should -Match 'Refusing to create a certificate with this CDP'
    }

    It 'keeps CRL numbers monotonic' {
        $certificateText | Should -Match '\$previous \+ 1'
        $certificateText | Should -Match 'ToUnixTimeMilliseconds'
        $certificateText | Should -Match 'Enter-GsaCrlPublicationLease'
        $certificateText | Should -Match "'x-ms-lease-duration'\s*=\s*'60'"
        $certificateText | Should -Match 'Invoke-GsaCrlPublicationLeaseRenewal'
    }

    It 'verifies the exact published CRL content' {
        $certificateText | Should -Match 'expectedHash'
        $certificateText | Should -Match 'downloadedHash'
    }

    It 'preserves active and transitional Graph certificates' {
        $certificateText | Should -Match "status -in 'active', 'enabled'"
        $certificateText | Should -Match 'include-unknown-enum-members'
        $certificateText | Should -Match 'unknownFutureValue'
        $certificateText | Should -Not -Match "Method DELETE.*externalCertificateAuthorityCertificates"
    }

    It 'keeps certificate enablement manual unless explicitly gated' {
        $certificateText | Should -Match 'AllowUndocumentedEnable'
        $certificateText | Should -Match 'Enable certificate.*Entra admin center'
    }
}

Describe 'Tenant scope safety contract' {
    It 'does not default forwarding profiles to disabled' {
        $postProvisionText | Should -Match "ToLowerInvariant\(\) -ne 'unchanged'"
        $postProvisionText | Should -Not -Match 'DesiredState\s*=\s*@\{\s*m365\s*=\s*\$false'
    }

    It 'gates beta functionality and keeps Internet baselines unassigned and disabled' {
        $scriptText | Should -Match 'GSA_ACCEPT_GRAPH_BETA_TERMS'
        $scriptText | Should -Match "state\s*=\s*'disabled'"
        $scriptText | Should -Match 'includeUsers\s*=\s*@\(\)'
        $scriptText | Should -Match 'includeGroups\s*=\s*@\(\)'
        $scriptText | Should -Match 'globalSecureAccessFilteringProfile'
        $postProvisionText | Should -Match 'Policy\.ReadWrite\.ConditionalAccess'
        $scriptText | Should -Not -Match 'priority\s*-eq\s*65000'
        $preProvisionText | Should -Not -Match "Get-GsaBoolean \`\$env:GSA_ENABLE_INTERNET_BASELINE\)\s*-or"
    }

    It 'requires an active connector before configuring Private Access' {
        $scriptText | Should -Match 'connectorGroups/\$ConnectorGroupId/members'
        $scriptText | Should -Match 'has no active connectors'
    }

    It 'keeps readiness validation free of tenant mutations' {
        $readinessText | Should -Match 'NetworkAccess\.Read\.All'
        $readinessText | Should -Match 'NetworkAccessPolicy\.Read\.All'
        $readinessText | Should -Match 'Directory\.ReadWrite\.All'
        $readinessText | Should -Match 'Test-GsaInternetBaseline'
        $readinessText | Should -Not -Match 'Invoke-MgGraphRequest\s+-Method\s+(POST|PATCH|PUT|DELETE)'
    }

    It 'keeps observability and client readiness plan-first and non-mutating' {
        $observabilityPlanText | Should -Match 'AcknowledgePlanId must exactly match'
        $observabilityPlanText | Should -Match 'diagnosticSettingsCategories\?api-version=2017-04-01-preview'
        $observabilityPlanText | Should -Match 'The Azure tenant does not match the ownership manifest'
        $observabilityPlanText | Should -Match 'Assert-GsaObservabilityPlanCurrent'
        $observabilityPlanText | Should -Match 'Write-GsaPendingTransaction'
        $observabilityPlanText.IndexOf('Write-GsaPendingTransaction') | Should -BeLessThan $observabilityPlanText.IndexOf('az deployment tenant create')
        $observabilityPlanText | Should -Match '\[switch\]\$Execute'
        $observabilityText | Should -Match 'explicitly supplied existing Log Analytics workspace'
        $observabilityText | Should -Match 'Existing unmanaged routes are preserved'
        $observabilityText | Should -Match 'Assignment is configuration evidence only'
        $observabilityText | Should -Match 'DestinationUrl'
        $observabilityText | Should -Match 'Content'
        $bicepText | Should -Not -Match 'Microsoft\.OperationalInsights/workspaces@'
    }

    It 'keeps remote-network and Adaptive Access operations plan-first and narrowly create-only' {
        $remoteNetworkPlanText | Should -Match 'AcknowledgePlanId must exactly match'
        $remoteNetworkPlanText | Should -Match '\[SecureString\]\$PreSharedKey'
        $remoteNetworkPlanText | Should -Match '\[switch\]\$Execute'
        $remoteNetworkPlanText | Should -Match 'Assert-GsaRemoteNetworkPlanCurrent'
        $remoteNetworkPlanText | Should -Match 'Write-GsaPendingTransaction'
        $remoteNetworkPlanText.IndexOf('Write-GsaPendingTransaction') | Should -BeLessThan $remoteNetworkPlanText.IndexOf("-Method POST -Uri '/beta/networkAccess/connectivity/remoteNetworks'")
        $remoteNetworkPlanText | Should -Not -Match 'Invoke-MgGraphRequest\s+-Method\s+(PATCH|PUT|DELETE)'
        $remoteNetworkInventoryText | Should -Not -Match 'Invoke-MgGraphRequest\s+-Method\s+(POST|PATCH|PUT|DELETE)'
        $remoteNetworkText | Should -Match 'Universal CAE is platform behavior, not a deployable resource'
        $remoteNetworkText | Should -Match 'existing remote networks, device links, and forwarding-profile associations are never mutated'
        $remoteNetworkPlanText | Should -Not -Match 'connectorGroups/.*/members.*-Method\s+(POST|PATCH|PUT|DELETE)'
        $remoteNetworkPlanText | Should -Match 'remoteNetworkCreated-deviceLinkPending'
        $remoteNetworkPlanText | Should -Match 'automatedRollback = \$false'
    }

    It 'never persists or prints remote-network shared secrets' {
        $fixtureText = (Get-ChildItem (Join-Path $repoRoot 'tests\fixtures') -Filter *.json | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
        $fixtureText | Should -Not -Match '(?i)pre.?shared.?key|\bpsk\b'
        $remoteNetworkPlanText | Should -Not -Match 'Write-(Host|Information|Output|Verbose|Debug).*PreSharedKey'
        $remoteNetworkPlanText | Should -Not -Match 'azd env set.*(?i:psk|pre.?shared)'
        $remoteNetworkPlanText | Should -Match "Remove\('preSharedKey'\)"
        $remoteNetworkPlanText | Should -Match 'Provider error details were suppressed because they might echo the sensitive request body'
    }

    It 'never assigns Intune profiles broadly by default' {
        $postProvisionText | Should -Match "GSA_INTUNE_ASSIGNMENT_MODE' -Default 'None'"
        $intuneText | Should -Match "AssignmentMode = 'None'"
        $intuneText | Should -Match "AssignmentMode -eq 'AllDevices'.*AcknowledgeLabMode"
    }

    It 'excludes Android Device Administrator and gates AOSP manually' {
        $intuneText | Should -Not -Match '#microsoft\.graph\.androidTrustedRootCertificate'
        $intuneText | Should -Match 'AndroidAOSP'
        $intuneText | Should -Match 'No validated typed Graph resource is documented'
    }
}

Describe 'Lifecycle state contract' {
    It 'pins the azd contract used by the state schema' {
        $azureYamlText | Should -Match 'requiredVersions:'
        $azureYamlText | Should -Match 'azd:\s*">= 1\.30\.0"'
        $azureYamlText | Should -Match 'azd-global-secure-access@0\.3\.0'
    }

    It 'writes pending state before mutations and commits only after enabled operations' {
        $postProvisionText.IndexOf('Write-GsaPendingTransaction') | Should -BeLessThan $postProvisionText.IndexOf('Enable-GsaTenantOnboarding')
        $postProvisionText.IndexOf('Complete-GsaStateTransaction') | Should -BeGreaterThan $postProvisionText.IndexOf('Set-GsaIntuneTrustedRoot')
        $stateText | Should -Match '\[IO\.File\]::Move\(\$temporaryPath,\s*\$resolved,\s*\$true\)'
    }

    It 'rejects secret-shaped fields and keeps ownership tied to exact IDs' {
        $stateText | Should -Match 'access\.\?token'
        $stateText | Should -Match 'PRIVATE KEY'
        $stateText | Should -Match '\$previous\.ownership -eq ''managed'''
        $stateText | Should -Match '\$previousManifest\.resources.*\$_.id -eq \$Id'
    }

    It 'preserves untouched resources and strong checks across execution-toggle changes' {
        $postProvisionText | Should -Match 'Merge-GsaStateResourceSet'
        $postProvisionText | Should -Match 'previousDesiredState\.internetBaseline\.enabled'
        $readinessText | Should -Match 'manifestHasInternetBaseline'
        $readinessText | Should -Match 'GSA_ENABLE_INTERNET_BASELINE\).*-or \$manifestHasInternetBaseline'
    }

    It 'uses a per-surface cloud matrix instead of broad national-cloud claims' {
        $commonText | Should -Match 'ForwardingRules'
        $commonText | Should -Match 'ForwardingMutation'
        $commonText | Should -Match 'DeploymentLogs'
        $commonText | Should -Match 'AzureUSGovernment'
        $commonText | Should -Match 'AzureChinaCloud'
    }

    It 'keeps ordinary azd down non-mutating for Microsoft Graph' {
        $azureYamlText | Should -Match 'predown:'
        $azureYamlText | Should -Match 'Invoke-PreDown\.ps1'
        $preDownText | Should -Not -Match 'Invoke-MgGraphRequest\s+-Method\s+(POST|PATCH|PUT|DELETE)'
        $preDownText | Should -Match 'performed no Microsoft Graph mutation'
    }

    It 'binds cleanup to exact managed IDs and preserves reused or active certificate objects' {
        $cleanupText | Should -Match '\$resource\.ownership -ne ''managed'''
        $cleanupText | Should -Match 'Names and natural identifiers do not grant deletion authority'
        $cleanupText | Should -Match 'Active certificates are never deleted'
        $cleanupText | Should -Match 'Root retirement requires verified replacement overlap'
    }

    It 'keeps forwarding recovery separate and acknowledgement gated' {
        $preDownText | Should -Not -Match 'Invoke-GsaForwardingRecovery'
        $recoveryText | Should -Match 'AcknowledgePlanId must exactly match'
        $recoveryText | Should -Match 'Assert-GsaPlanCurrent'
        $recoveryText | Should -Match 'RestoreCapturedState'
    }
}
