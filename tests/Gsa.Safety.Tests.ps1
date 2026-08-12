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
    $certificateText = Get-Content (Join-Path $repoRoot 'scripts\modules\Gsa.Certificate.psm1') -Raw
    $intuneText = Get-Content (Join-Path $repoRoot 'scripts\modules\Gsa.Intune.psm1') -Raw
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
        $readinessText | Should -Match 'Directory\.ReadWrite\.All'
        $readinessText | Should -Match 'Test-GsaInternetBaseline'
        $readinessText | Should -Not -Match 'Invoke-MgGraphRequest\s+-Method\s+(POST|PATCH|PUT|DELETE)'
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
