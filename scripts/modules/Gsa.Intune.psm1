Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Gsa.Common.psm1') -Force

function Set-GsaIntuneTrustedRoot {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)]
        [ValidateSet(
            'Windows',
            'macOS',
            'iOS/iPadOS',
            'AndroidEnterpriseDeviceOwner',
            'AndroidEnterpriseWorkProfile',
            'AndroidAOSP'
        )]
        [string[]]$Platforms,
        [ValidateSet('None', 'PilotGroup', 'AllDevices')]
        [string]$AssignmentMode = 'None',
        [guid]$PilotGroupId,
        [switch]$AcknowledgeLabMode,
        [switch]$AllowAdditionalAssignments
    )

    Assert-GsaPreviewGate -Feature 'Intune trusted-root profile creation' -Enabled $true
    if ($AssignmentMode -eq 'PilotGroup' -and $PilotGroupId -eq [guid]::Empty) {
        throw 'PilotGroup assignment requires GSA_PILOT_GROUP_ID.'
    }
    if ($AssignmentMode -eq 'AllDevices' -and -not $AcknowledgeLabMode) {
        throw 'AllDevices assignment requires GSA_ACKNOWLEDGE_LAB_MODE=true.'
    }

    $platformMap = @{
        Windows = @{
            Type  = '#microsoft.graph.windows81TrustedRootCertificate'
            Label = 'Windows'
            Extra = @{ destinationStore = 'computerCertStoreRoot' }
        }
        macOS = @{
            Type  = '#microsoft.graph.macOSTrustedRootCertificate'
            Label = 'macOS'
            Extra = @{ deploymentChannel = 'deviceChannel' }
        }
        'iOS/iPadOS' = @{
            Type  = '#microsoft.graph.iosTrustedRootCertificate'
            Label = 'iOS-iPadOS'
            Extra = @{}
        }
        AndroidEnterpriseDeviceOwner = @{
            Type  = '#microsoft.graph.androidDeviceOwnerTrustedRootCertificate'
            Label = 'Android Enterprise Device Owner'
            Extra = @{}
        }
        AndroidEnterpriseWorkProfile = @{
            Type  = '#microsoft.graph.androidWorkProfileTrustedRootCertificate'
            Label = 'Android Enterprise Work Profile'
            Extra = @{}
        }
    }
    $base64 = [Convert]::ToBase64String($Certificate.RawData)
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($platform in $Platforms) {
        if ($platform -eq 'AndroidAOSP') {
            $results.Add([pscustomobject]@{
                Platform   = $platform
                Id         = $null
                Status     = 'Manual'
                ManualStep = 'Create an Android AOSP Device Owner trusted certificate profile in Intune. No validated typed Graph resource is documented.'
            })
            continue
        }

        $definition = $platformMap[$platform]
        $name = "GSA TLS Root - $($definition.Label)"
        $escaped = $name.Replace("'", "''")
        $encodedFilter = [uri]::EscapeDataString("displayName eq '$escaped'")
        $profiles = @(Get-GsaGraphCollection -Uri "/beta/deviceManagement/deviceConfigurations?`$filter=$encodedFilter")
        $profileMatches = @($profiles | Where-Object { $_.'@odata.type' -eq $definition.Type })
        if ($profileMatches.Count -gt 1) {
            throw "Multiple Intune profiles named '$name' with type '$($definition.Type)' exist."
        }

        $body = @{
            '@odata.type'          = $definition.Type
            displayName            = $name
            description            = 'Trusted root for Global Secure Access TLS inspection; managed by azd-global-secure-access'
            trustedRootCertificate = $base64
            certFileName            = 'gsa-tls-root-ca.cer'
        }
        foreach ($extra in $definition.Extra.GetEnumerator()) {
            $body[$extra.Key] = $extra.Value
        }

        $intuneProfile = $profileMatches | Select-Object -First 1
        $changed = $false
        $created = $false
        if (-not $intuneProfile) {
            if ($PSCmdlet.ShouldProcess($name, 'Create Intune trusted-root profile')) {
                $intuneProfile = Invoke-MgGraphRequest -Method POST -Uri '/beta/deviceManagement/deviceConfigurations' -Body ($body | ConvertTo-Json -Depth 6) -ContentType 'application/json' -OutputType PSObject
                $changed = $true
                $created = $true
            }
        } elseif ($intuneProfile.trustedRootCertificate -ne $base64) {
            if ($PSCmdlet.ShouldProcess($name, 'Update Intune trusted-root certificate while preserving assignments')) {
                Invoke-MgGraphRequest -Method PATCH -Uri "/beta/deviceManagement/deviceConfigurations/$($intuneProfile.id)" -Body ($body | ConvertTo-Json -Depth 6) -ContentType 'application/json' | Out-Null
                $changed = $true
            }
        }

        if ($intuneProfile -and $AssignmentMode -ne 'None') {
            $current = @(Get-GsaGraphCollection -Uri "/v1.0/deviceManagement/deviceConfigurations/$($intuneProfile.id)/assignments")
            $targetType = if ($AssignmentMode -eq 'AllDevices') {
                '#microsoft.graph.allDevicesAssignmentTarget'
            } else {
                '#microsoft.graph.groupAssignmentTarget'
            }
            $targetGroupId = if ($AssignmentMode -eq 'PilotGroup') { [string]$PilotGroupId } else { $null }
            $exists = @($current | Where-Object {
                $_.target.'@odata.type' -eq $targetType -and
                ($AssignmentMode -ne 'PilotGroup' -or $_.target.groupId -eq $targetGroupId)
            }).Count -gt 0
            $additionalAssignments = @($current | Where-Object {
                $_.target.'@odata.type' -ne $targetType -or
                ($AssignmentMode -eq 'PilotGroup' -and $_.target.groupId -ne $targetGroupId)
            })
            if ($additionalAssignments.Count -gt 0 -and -not $AllowAdditionalAssignments) {
                throw "Intune profile '$name' has assignments outside the desired $AssignmentMode target. Review them manually or explicitly allow additional assignments."
            }
            if (-not $exists) {
                $assignments = @($current | ForEach-Object { @{ target = $_.target } })
                $target = @{ '@odata.type' = $targetType }
                if ($targetGroupId) {
                    $target.groupId = $targetGroupId
                }
                $assignments += @{ target = $target }
                $assignmentBody = @{ assignments = $assignments } | ConvertTo-Json -Depth 10
                if ($PSCmdlet.ShouldProcess($name, "Add $AssignmentMode assignment")) {
                    Invoke-MgGraphRequest -Method POST -Uri "/v1.0/deviceManagement/deviceConfigurations/$($intuneProfile.id)/assign" -Body $assignmentBody -ContentType 'application/json' | Out-Null
                    $changed = $true
                }
            }
        }

        $results.Add([pscustomobject]@{
            Platform   = $platform
            Id         = if ($intuneProfile) { $intuneProfile.id } else { $null }
            Name       = $name
            Status     = if ($changed) { 'Changed' } else { 'Current' }
            Created    = $created
            ManualStep = $null
            AssignmentMode = $AssignmentMode
        })
    }
    return $results.ToArray()
}

Export-ModuleMember -Function 'Set-GsaIntuneTrustedRoot'
