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
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$SubscribedSkus
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
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Memberships
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
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Connectors,
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
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Certificates,
        [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow
    )

    $checks = [System.Collections.Generic.List[object]]::new()
    if ($Certificates.Count -eq 0) {
        $checks.Add((ConvertTo-GsaReadinessCheck -Name 'TLS certificate readiness' -Status 'Fail' -Classification 'missing' `
            -Detail 'No TLS inspection certificates were returned for the requested or committed TLS inspection feature.' `
            -Expected 'One or more TLS inspection certificates' -Actual @()))
    }
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

    # Project only closed evidence; never serialize the supplied CRL/provider DTO.
    $publishedProperty = $CrlState.PSObject.Properties['published']
    $published = $null -ne $publishedProperty -and $publishedProperty.Value -is [bool] -and $publishedProperty.Value
    $hashes = @{}
    foreach ($name in @('expectedSha256', 'actualSha256')) {
        $property = $CrlState.PSObject.Properties[$name]
        $hashes[$name] = if ($null -ne $property -and $property.Value -is [string] -and $property.Value -cmatch '\A[a-fA-F0-9]{64}\z') {
            $property.Value.ToUpperInvariant()
        } else { $null }
    }
    $hashMatches = $null -ne $hashes.expectedSha256 -and $null -ne $hashes.actualSha256 -and $hashes.expectedSha256 -ceq $hashes.actualSha256
    $dateProperty = $CrlState.PSObject.Properties['nextUpdate']
    $committedDate = [DateTimeOffset]::MinValue
    $datePresent = $null -ne $dateProperty -and $null -ne $dateProperty.Value -and $dateProperty.Value -cne ''
    $dateValid = $datePresent -and $dateProperty.Value -is [string] -and $dateProperty.Value.Length -le 40 -and
        $dateProperty.Value -cmatch '\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})\z' -and
        [DateTimeOffset]::TryParse($dateProperty.Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$committedDate)
    $actual = [ordered]@{
        published = [bool]$published
        expectedSha256 = $hashes.expectedSha256
        actualSha256 = $hashes.actualSha256
        hashMatches = [bool]$hashMatches
        publicationVerified = [bool]($published -and $hashMatches)
        # Retain the legacy field as an explicitly labelled committed-date alias.
        nextUpdate = if ($dateValid) { $committedDate.ToUniversalTime().ToString('O') } else { $null }
        nextUpdateSource = 'committedState'
        observedNextUpdate = $null
        expiryObserved = $false
        failureCode = 'ObservedExpiryUnknown'
    }
    $status = 'Warning'
    $classification = 'unknownTransitional'
    $detail = 'Published bytes match committed SHA-256. The recorded expiry is advisory; expiry and issuer trust were not observed from CRL bytes.'
    if (-not $published) {
        $status = 'Fail'; $classification = 'missing'; $actual.failureCode = 'PublicationUnavailable'
        $detail = 'The configured CRL publication could not be observed as HTTP 200 with CRL content type.'
    } elseif ($null -eq $hashes.expectedSha256 -or $null -eq $hashes.actualSha256) {
        $status = 'Fail'; $classification = 'unknownTransitional'; $actual.failureCode = 'HashEvidenceInvalid'
        $detail = 'Valid committed and observed SHA-256 fingerprints are required to verify publication.'
    } elseif (-not $hashMatches) {
        $status = 'Fail'; $classification = 'changed'; $actual.failureCode = 'HashMismatch'
        $detail = 'The published CRL bytes do not match the committed SHA-256 fingerprint.'
    } elseif (-not $datePresent) {
        $actual.failureCode = 'CommittedExpiryMissing'
        $detail = 'Published bytes match committed SHA-256, but no expiry is recorded in committed state.'
    } elseif (-not $dateValid) {
        $actual.failureCode = 'CommittedExpiryInvalid'
        $detail = 'Published bytes match committed SHA-256, but the recorded expiry is invalid.'
    } elseif ($committedDate -le $Now) {
        $status = 'Fail'; $classification = 'changed'; $actual.failureCode = 'CommittedExpiryExpired'
        $detail = 'The committed CRL expiry date has passed; expiry was not observed from CRL bytes.'
    } elseif ($committedDate -le $Now.AddDays(7)) {
        $classification = 'changed'; $actual.failureCode = 'CommittedExpiryNear'
        $detail = 'The committed CRL expiry date is within seven days; expiry was not observed from CRL bytes.'
    }
    return ConvertTo-GsaReadinessCheck -Name 'CRL publication' -Status $status -Classification $classification `
        -Detail $detail -Expected 'Exact published bytes and separately qualified committed expiry' -Actual ([pscustomobject]$actual)
}

function Get-GsaBoundedCrlEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Uri,
        [ValidateRange(1, 1048576)][int] $MaximumBytes = 1048576,
        [ValidateScript({ $_ -gt [TimeSpan]::Zero -and $_ -le [TimeSpan]::FromSeconds(15) })]
        [TimeSpan] $TotalTimeout = ([TimeSpan]::FromSeconds(15))
    )

    $closed = [pscustomobject][ordered]@{
        published    = $false
        actualSha256 = $null
    }
    $parsedUri = $null
    if (-not [Uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsedUri) -or
        $parsedUri.Scheme -notin @('http', 'https') -or -not $parsedUri.Host -or
        $parsedUri.UserInfo -or $parsedUri.Fragment) {
        return $closed
    }

    $handler = $null
    $client = $null
    $request = $null
    $response = $null
    $stream = $null
    $buffered = $null
    $deadline = $null
    try {
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $false
        $handler.UseProxy = $false
        $handler.UseCookies = $false
        $handler.UseDefaultCredentials = $false
        $handler.Credentials = $null
        $handler.DefaultProxyCredentials = $null
        $handler.PreAuthenticate = $false

        $client = [Net.Http.HttpClient]::new($handler, $true)
        $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
        $deadline = [Threading.CancellationTokenSource]::new($TotalTimeout)
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $parsedUri)
        $request.Headers.Accept.Add([Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('application/pkix-crl'))
        $response = $client.SendAsync(
            $request,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
            $deadline.Token
        ).GetAwaiter().GetResult()

        $contentType = $response.Content.Headers.ContentType
        $contentLength = $response.Content.Headers.ContentLength
        if ($response.StatusCode -ne [Net.HttpStatusCode]::OK -or
            $null -eq $contentType -or $contentType.MediaType -ine 'application/pkix-crl' -or
            $contentType.Parameters.Count -ne 0 -or
            ($null -ne $contentLength -and ($contentLength -le 0 -or $contentLength -gt $MaximumBytes))) {
            return $closed
        }

        $stream = $response.Content.ReadAsStreamAsync($deadline.Token).GetAwaiter().GetResult()
        $buffered = [IO.MemoryStream]::new()
        $buffer = [byte[]]::new(8192)
        $total = 0
        while (($read = $stream.ReadAsync($buffer, 0, $buffer.Length, $deadline.Token).GetAwaiter().GetResult()) -gt 0) {
            if ($total + $read -gt $MaximumBytes) { return $closed }
            $buffered.Write($buffer, 0, $read)
            $total += $read
        }
        if ($total -eq 0 -or ($null -ne $contentLength -and $total -ne $contentLength)) { return $closed }

        $bytes = $buffered.ToArray()
        return [pscustomobject][ordered]@{
            published    = $true
            actualSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
        }
    }
    catch {
        return $closed
    }
    finally {
        if ($buffered) { $buffered.Dispose() }
        if ($stream) { $stream.Dispose() }
        if ($response) { $response.Dispose() }
        if ($request) { $request.Dispose() }
        if ($deadline) { $deadline.Dispose() }
        if ($client) { $client.Dispose() }
        elseif ($handler) { $handler.Dispose() }
    }
}

function Test-GsaMicrosoftTrafficRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Policies
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
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Deployments
    )

    $checks = [System.Collections.Generic.List[object]]::new()
    if ($Deployments.Count -eq 0) {
        $checks.Add((ConvertTo-GsaReadinessCheck -Name 'Deployment logs' -Status 'Warning' -Classification 'missing' `
            -Detail 'No deployment history was returned. No deployment success was observed.' `
            -Expected 'Observable deployment history' -Actual @()))
    }
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
    'Get-GsaBoundedCrlEvidence',
    'Test-GsaDeployment',
    'Test-GsaDirectoryRoleIndicator',
    'Test-GsaLicenseIndicator',
    'Test-GsaMicrosoftTrafficRule',
    'Test-GsaStateTransactionReadiness'
)
