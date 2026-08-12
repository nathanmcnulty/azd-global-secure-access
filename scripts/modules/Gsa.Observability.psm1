Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Gsa.State.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Gsa.Readiness.psm1') -Force

$script:GsaDiagnosticCategories = [ordered]@{
    NetworkAccessTrafficLogs = [ordered]@{ table = 'NetworkAccessTraffic'; maturity = 'ga'; privacy = 'aggregateOnly' }
    AuditLogs = [ordered]@{ table = 'AuditLogs'; maturity = 'preview'; privacy = 'aggregateOnly' }
    EnrichedOffice365AuditLogs = [ordered]@{ table = 'EnrichedOffice365AuditLogs'; maturity = 'preview'; privacy = 'aggregateOnly' }
    RemoteNetworkHealthLogs = [ordered]@{ table = 'RemoteNetworkHealthLogs'; maturity = 'preview'; privacy = 'aggregateOnly' }
    NetworkAccessGenerativeAIInsights = [ordered]@{ table = 'NetworkAccessGenerativeAIInsights'; maturity = 'preview'; privacy = 'contentExcluded' }
}

function Get-GsaObservabilityValue {
    param([AllowNull()][object]$InputObject, [Parameter(Mandatory)][string]$Name)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        return $(if ($InputObject.Contains($Name)) { $InputObject[$Name] } else { $null })
    }
    return $(if ($InputObject.PSObject.Properties[$Name]) { $InputObject.$Name } else { $null })
}

function Get-GsaDiagnosticCategoryCatalog {
    [CmdletBinding()]
    param()

    return ConvertTo-GsaCanonicalValue -Value $script:GsaDiagnosticCategories
}

function Get-GsaObservabilityArtifactPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('plan-json', 'plan-text', 'assets-json')][string]$Type,
        [string]$ProjectRoot,
        [string]$EnvironmentName = $env:AZURE_ENV_NAME
    )

    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
        $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    }
    if ([string]::IsNullOrWhiteSpace($EnvironmentName)) {
        throw 'AZURE_ENV_NAME is required to resolve observability artifacts.'
    }
    $fileName = switch ($Type) {
        'plan-json' { 'gsa-observability-plan.json' }
        'plan-text' { 'gsa-observability-plan.txt' }
        'assets-json' { 'gsa-observability-assets.json' }
    }
    return Join-Path (Join-Path (Join-Path $ProjectRoot '.azure') $EnvironmentName) $fileName
}

function Get-GsaDiagnosticSettingProjection {
    param([Parameter(Mandatory)][object]$Setting)

    $properties = Get-GsaObservabilityValue -InputObject $Setting -Name properties
    $logs = @(Get-GsaObservabilityValue -InputObject $properties -Name logs)
    return [ordered]@{
        id = [string](Get-GsaObservabilityValue -InputObject $Setting -Name id)
        name = [string](Get-GsaObservabilityValue -InputObject $Setting -Name name)
        workspaceId = [string](Get-GsaObservabilityValue -InputObject $properties -Name workspaceId)
        categories = @(
            $logs |
                Where-Object { (Get-GsaObservabilityValue -InputObject $_ -Name enabled) -eq $true } |
                ForEach-Object { [string](Get-GsaObservabilityValue -InputObject $_ -Name category) } |
                Where-Object { $_ } |
                Sort-Object -Unique
        )
    }
}

function Get-GsaObservabilityPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$DiscoveredCategories,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ExistingSettings,
        [AllowNull()][object]$Manifest,
        [string]$SettingName = 'gsa-observability',
        [string[]]$RequestedCategories = @($script:GsaDiagnosticCategories.Keys),
        [string[]]$AvailableTables = @(),
        [DateTimeOffset]$GeneratedAt = [DateTimeOffset]::UtcNow
    )

    if ($WorkspaceResourceId -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.OperationalInsights/workspaces/[^/]+$') {
        throw 'WorkspaceResourceId must be the full resource ID of an explicitly supplied existing Log Analytics workspace.'
    }

    $catalog = Get-GsaDiagnosticCategoryCatalog
    $requested = @($RequestedCategories | Sort-Object -Unique)
    $discovered = @($DiscoveredCategories | Sort-Object -Unique)
    $unknownRequested = @($requested | Where-Object { -not $catalog.Contains($_) })
    if ($unknownRequested.Count -gt 0) {
        throw "Requested diagnostic categories are not in the documented catalog: $($unknownRequested -join ', ')."
    }

    $settings = @($ExistingSettings | ForEach-Object { Get-GsaDiagnosticSettingProjection -Setting $_ } | Sort-Object id)
    $targetId = "/providers/Microsoft.AADIAM/diagnosticSettings/$SettingName"
    $manifestResource = if ($Manifest -and $Manifest.PSObject.Properties['resources']) {
        @($Manifest.resources | Where-Object { $_.key -eq "diagnosticSetting:$SettingName" }) | Select-Object -First 1
    } else { $null }
    $targetSetting = @($settings | Where-Object { $_.id -eq $targetId -or $_.name -eq $SettingName }) | Select-Object -First 1
    $managedTarget = $manifestResource -and $manifestResource.ownership -eq 'managed' -and $manifestResource.id -eq $targetId

    $categoryActions = [System.Collections.Generic.List[object]]::new()
    foreach ($category in $requested) {
        $definition = $catalog[$category]
        $available = $category -in $discovered
        $existingRoutes = @($settings | Where-Object { $_.workspaceId -eq $WorkspaceResourceId -and $category -in $_.categories })
        $disposition = if (-not $available) {
            'unavailable'
        } elseif ($existingRoutes.Count -gt 0) {
            'preserve-existing'
        } elseif ($targetSetting -and -not $managedTarget) {
            'blocked-conflict'
        } elseif ($targetSetting -and $managedTarget) {
            'eligible-update'
        } else {
            'eligible-create'
        }
        $categoryActions.Add([pscustomobject][ordered]@{
            category = $category
            table = $definition.table
            maturity = $definition.maturity
            discovered = $available
            tableObserved = $definition.table -in $AvailableTables
            disposition = $disposition
            existingRouteIds = @($existingRoutes | ForEach-Object { $_.id })
            reason = switch ($disposition) {
                'unavailable' { 'The tenant did not expose this category during discovery; no configuration is proposed.' }
                'preserve-existing' { 'An existing route already sends this category to the supplied workspace; it is preserved without ownership inference.' }
                'blocked-conflict' { 'The requested setting name is occupied by an object not bound as managed by exact ID in the ownership manifest.' }
                'eligible-update' { 'The exact diagnostic setting ID is recorded as managed and can be considered for a separately acknowledged, stale-checked update.' }
                'eligible-create' { 'The category is exposed and no existing route covers it; creation is only proposed, not performed.' }
            }
        })
    }

    $inventory = [ordered]@{
        workspaceResourceId = $WorkspaceResourceId
        discoveredCategories = $discovered
        existingSettings = $settings
        availableTables = @($AvailableTables | Sort-Object -Unique)
    }
    $identity = [ordered]@{
        schemaVersion = '1.0.0'
        type = 'observability-plan'
        settingName = $SettingName
        manifestFingerprint = if ($Manifest) { Get-GsaStateFingerprint -Value $Manifest } else { $null }
        inventoryFingerprint = Get-GsaStateFingerprint -Value $inventory
        categoryActions = @($categoryActions)
    }
    return [pscustomobject][ordered]@{
        schemaVersion = '1.0.0'
        planId = Get-GsaStateFingerprint -Value $identity
        type = 'observability-plan'
        generatedAt = $GeneratedAt.ToUniversalTime().ToString('O')
        mutationPerformed = $false
        settingName = $SettingName
        targetId = $targetId
        targetOwnership = if ($managedTarget) { 'managed' } elseif ($targetSetting) { 'unmanagedConflict' } else { 'unclaimed' }
        manifestFingerprint = $identity.manifestFingerprint
        inventoryFingerprint = $identity.inventoryFingerprint
        inventory = $inventory
        categoryActions = @($categoryActions)
        guidance = [ordered]@{
            mechanism = 'Microsoft Entra tenant diagnostic settings use the stable Microsoft.AADIAM/diagnosticSettings resource mechanism.'
            preview = 'Category availability and maturity vary by tenant. Preview categories are never assumed from documentation alone.'
            ingestion = 'A configured route and assignment are evidence only. Tables appear after data is ingested, and ingestion can be delayed.'
            ownership = 'Only an exact managed object ID in the committed GSA manifest grants future update authority. Existing unmanaged routes are preserved.'
        }
    }
}

function Get-GsaObservabilityAsset {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Plan)

    $queries = [ordered]@{
        trafficEvidence = @'
union isfuzzy=true NetworkAccessTraffic
| extend EventTime = todatetime(column_ifexists("TimeGenerated", datetime(null)))
| where EventTime > ago(24h)
| summarize Events=count(), LastSeen=max(EventTime)
'@
        remoteNetworkHealth = @'
union isfuzzy=true RemoteNetworkHealthLogs
| extend EventTime=todatetime(column_ifexists("TimeGenerated", datetime(null))), Health=tostring(column_ifexists("HealthStatus", column_ifexists("Status", "unknown")))
| where EventTime > ago(30m)
| summarize Events=count(), Unhealthy=countif(Health !in~ ("healthy", "connected", "up")), LastSeen=max(EventTime) by Health
'@
        deploymentErrors = @'
union isfuzzy=true AuditLogs, NetworkAccessAlerts
| extend EventTime=todatetime(column_ifexists("TimeGenerated", datetime(null))), Result=tostring(column_ifexists("Result", column_ifexists("ResultType", column_ifexists("Severity", "unknown"))))
| where EventTime > ago(24h)
| where Result has_any ("fail", "error", "high", "critical")
| summarize Events=count(), LastSeen=max(EventTime) by Result
'@
        certificateExpiry = @'
GsaCertificateInventory_CL
| extend NotAfter=todatetime(column_ifexists("NotAfter_t", datetime(null))), Name=tostring(column_ifexists("Name_s", "unknown"))
| where isnotnull(NotAfter) and NotAfter < now() + 90d
| project Name, NotAfter, DaysRemaining=datetime_diff("day", NotAfter, now())
'@
        crlExpiry = @'
GsaCrlInventory_CL
| extend NextUpdate=todatetime(column_ifexists("NextUpdate_t", datetime(null))), Url=tostring(column_ifexists("Url_s", "redacted"))
| where isnotnull(NextUpdate) and NextUpdate < now() + 7d
| project Url, NextUpdate, DaysRemaining=datetime_diff("day", NextUpdate, now())
'@
    }
    $enabledCategories = @($Plan.categoryActions | Where-Object disposition -in 'preserve-existing', 'eligible-create', 'eligible-update')
    $observedTables = @($Plan.inventory.availableTables)
    return [pscustomobject][ordered]@{
        schemaVersion = '1.0.0'
        planId = $Plan.planId
        privacy = [ordered]@{
            default = 'aggregate-only'
            excludedFields = @('Content', 'DestinationUrl', 'DestinationFqdn', 'UserPrincipalName', 'SourceIp')
            note = 'Queries report counts, status, and timestamps by default; sensitive browsing and prompt content are not selected.'
        }
        prerequisites = [ordered]@{
            configuredCategories = @($enabledCategories.category)
            observedTables = $observedTables
            missingTablesAreHealthy = $false
        }
        workbooks = @(
            [ordered]@{ name = 'GSA operational evidence'; coverage = 'partial'; enabled = ('NetworkAccessTraffic' -in $observedTables); queries = @('trafficEvidence', 'remoteNetworkHealth', 'deploymentErrors') },
            [ordered]@{ name = 'GSA certificate and CRL expiry'; coverage = 'state-export-dependent'; enabled = ('GsaCertificateInventory_CL' -in $observedTables -or 'GsaCrlInventory_CL' -in $observedTables); queries = @('certificateExpiry', 'crlExpiry') }
        )
        alerts = @(
            [ordered]@{ name = 'GSA remote network unhealthy evidence'; query = 'remoteNetworkHealth'; enabledByDefault = $false; reason = 'Enable only after the table is observed and a baseline is established.' },
            [ordered]@{ name = 'GSA deployment error evidence'; query = 'deploymentErrors'; enabledByDefault = $false; reason = 'Schema and category availability vary.' },
            [ordered]@{ name = 'GSA certificate expiry evidence'; query = 'certificateExpiry'; enabledByDefault = $false; reason = 'Requires explicit non-secret state inventory ingestion.' },
            [ordered]@{ name = 'GSA CRL expiry evidence'; query = 'crlExpiry'; enabledByDefault = $false; reason = 'Requires explicit non-secret state inventory ingestion.' }
        )
        queries = $queries
    }
}

function Test-GsaObservabilityEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Plan)

    $checks = [System.Collections.Generic.List[object]]::new()
    $workspaceId = [string](Get-GsaObservabilityValue -InputObject $Plan.inventory -Name workspaceResourceId)
    $checks.Add((ConvertTo-GsaReadinessCheck -Name 'Existing Log Analytics workspace evidence' -Status 'Info' -Classification 'reused' `
        -Detail 'The workspace was explicitly supplied as an existing destination. This repository did not create it or infer ownership.' `
        -Expected 'Existing workspace resource ID' -Actual $workspaceId))

    foreach ($action in @($Plan.categoryActions)) {
        $status = switch ($action.disposition) {
            'blocked-conflict' { 'Fail' }
            'unavailable' { 'Info' }
            'preserve-existing' { 'Pass' }
            default { 'Warning' }
        }
        $classification = switch ($action.disposition) {
            'blocked-conflict' { 'unmanagedConflict' }
            'unavailable' { 'unsupported' }
            'preserve-existing' { 'reused' }
            'eligible-update' { 'managed' }
            default { 'missing' }
        }
        $tableDetail = if ($action.tableObserved) {
            "Table '$($action.table)' was observed."
        } else {
            "Table '$($action.table)' was not observed; ingestion can be delayed, so absence is inconclusive rather than healthy."
        }
        $checks.Add((ConvertTo-GsaReadinessCheck -Name "Diagnostic category evidence: $($action.category)" -Status $status -Classification $classification `
            -Detail "$($action.reason) $tableDetail" -Expected 'Discovered category, preserved route, and observed ingestion evidence' `
            -Actual (ConvertTo-GsaCanonicalValue -Value $action)))
    }
    return $checks.ToArray()
}

function Test-GsaClientEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Evidence)

    $checks = [System.Collections.Generic.List[object]]::new()
    $clients = @(Get-GsaObservabilityValue -InputObject $Evidence -Name clients)
    if ($clients.Count -eq 0) {
        $checks.Add((ConvertTo-GsaReadinessCheck -Name 'Client evidence' -Status 'Info' -Classification 'missing' `
            -Detail 'No privacy-safe endpoint evidence was supplied. Assignment alone is not treated as installation, acquisition, forwarding, or health.' `
            -Expected 'Optional sanitized client evidence' -Actual $null))
    }
    foreach ($client in $clients) {
        $platform = [string](Get-GsaObservabilityValue -InputObject $client -Name platform)
        $health = [string](Get-GsaObservabilityValue -InputObject $client -Name health)
        $knownHealth = $health -in 'healthy', 'unhealthy', 'unknown'
        $status = if (-not $knownHealth -or $health -eq 'unknown') { 'Warning' } elseif ($health -eq 'unhealthy') { 'Fail' } else { 'Pass' }
        $classification = if (-not $knownHealth -or $health -eq 'unknown') { 'unknownTransitional' } elseif ($health -eq 'unhealthy') { 'changed' } else { 'reused' }
        $checks.Add((ConvertTo-GsaReadinessCheck -Name "Client health evidence: $platform" -Status $status -Classification $classification `
            -Detail "Observed sanitized client health '$health'. Assignment evidence is reported separately and does not prove acquisition." `
            -Expected 'healthy' -Actual (ConvertTo-GsaCanonicalValue -Value $client)))
    }

    foreach ($assignmentName in 'clientAssignment', 'trustedRootAssignment') {
        $assignment = Get-GsaObservabilityValue -InputObject $Evidence -Name $assignmentName
        if ($assignment) {
            $checks.Add((ConvertTo-GsaReadinessCheck -Name $assignmentName -Status 'Info' -Classification 'reused' `
                -Detail 'Assignment is configuration evidence only; it does not prove installation, trusted-root presence, traffic acquisition, forwarding, or health.' `
                -Expected 'Evidence only' -Actual (ConvertTo-GsaCanonicalValue -Value $assignment)))
        }
    }

    $conflicts = Get-GsaObservabilityValue -InputObject $Evidence -Name conflicts
    if ($conflicts) {
        foreach ($name in 'vpn', 'dnsNrpt', 'quic', 'hyperV', 'wsl', 'manualProxy', 'mobileDefender') {
            $value = [string](Get-GsaObservabilityValue -InputObject $conflicts -Name $name)
            if (-not $value) { continue }
            $known = $value -in 'clear', 'detected', 'unknown', 'notApplicable'
            $status = if (-not $known -or $value -eq 'unknown') { 'Warning' } elseif ($value -eq 'detected') { 'Warning' } else { 'Info' }
            $classification = if (-not $known -or $value -eq 'unknown') { 'unknownTransitional' } elseif ($value -eq 'detected') { 'changed' } else { 'reused' }
            $checks.Add((ConvertTo-GsaReadinessCheck -Name "Client conflict evidence: $name" -Status $status -Classification $classification `
                -Detail "Observed non-mutating conflict signal '$value'. Review on the endpoint; this report changed no client, VPN, DNS, proxy, virtualization, or Defender setting." `
                -Expected 'clear or notApplicable' -Actual $value))
        }
    }
    return $checks.ToArray()
}

function ConvertTo-GsaObservabilityPlanText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Plan)

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("Global Secure Access observability plan $($Plan.planId)")
    $lines.Add("Workspace: $($Plan.inventory.workspaceResourceId)")
    $lines.Add("Inventory fingerprint: $($Plan.inventoryFingerprint)")
    $lines.Add('No tenant or Azure mutation was performed.')
    $lines.Add('')
    foreach ($action in $Plan.categoryActions) {
        $lines.Add("[$($action.disposition)] $($action.category) ($($action.maturity)) - $($action.reason)")
    }
    return $lines -join [Environment]::NewLine
}

function Assert-GsaObservabilityPlanCurrent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$CurrentPlan,
        [AllowNull()][object]$Manifest
    )

    if ($Plan.type -ne 'observability-plan') { throw 'The supplied artifact is not a GSA observability plan.' }
    if ($Plan.planId -ne $CurrentPlan.planId) { throw 'The observability plan is stale because current diagnostic evidence changed.' }
    $manifestFingerprint = if ($Manifest) { Get-GsaStateFingerprint -Value $Manifest } else { $null }
    if ($Plan.manifestFingerprint -ne $manifestFingerprint) { throw 'The ownership manifest changed after the observability plan was created.' }
}

function Get-GsaObservabilityDeploymentTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object[]]$CurrentSettings
    )

    $blocked = @($Plan.categoryActions | Where-Object disposition -eq 'blocked-conflict')
    if ($blocked.Count -gt 0) { throw 'The observability plan contains an unmanaged conflict and cannot be deployed.' }
    $categories = @($Plan.categoryActions | Where-Object disposition -in 'eligible-create', 'eligible-update' | ForEach-Object category | Sort-Object -Unique)
    if ($categories.Count -eq 0) { throw 'The observability plan contains no managed diagnostic-setting changes.' }

    $target = @($CurrentSettings | Where-Object {
        (Get-GsaObservabilityValue -InputObject $_ -Name id) -eq $Plan.targetId -or
        (Get-GsaObservabilityValue -InputObject $_ -Name name) -eq $Plan.settingName
    }) | Select-Object -First 1
    $properties = if ($target) {
        $raw = Get-GsaObservabilityValue -InputObject $target -Name properties
        $raw | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable -Depth 100
    } else {
        [ordered]@{ workspaceId = $Plan.inventory.workspaceResourceId; logs = @() }
    }
    if ([string]$properties.workspaceId -ne [string]$Plan.inventory.workspaceResourceId) {
        throw 'The current target diagnostic setting destination does not match the reviewed workspace.'
    }
    $logs = @($properties.logs)
    foreach ($category in $categories) {
        $existing = @($logs | Where-Object { $_.category -eq $category }) | Select-Object -First 1
        if ($existing) {
            $existing.enabled = $true
        } else {
            $logs += [ordered]@{ category = $category; enabled = $true }
        }
    }
    $properties.logs = @($logs | Sort-Object { [string]$_.category })

    return [ordered]@{
        '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
        contentVersion = '1.0.0.0'
        resources = @(
            [ordered]@{
                type = 'Microsoft.AADIAM/diagnosticSettings'
                apiVersion = '2017-04-01'
                name = $Plan.settingName
                properties = $properties
            }
        )
    }
}

Export-ModuleMember -Function @(
    'Assert-GsaObservabilityPlanCurrent',
    'ConvertTo-GsaObservabilityPlanText',
    'Get-GsaDiagnosticCategoryCatalog',
    'Get-GsaObservabilityArtifactPath',
    'Get-GsaObservabilityAsset',
    'Get-GsaObservabilityDeploymentTemplate',
    'Get-GsaObservabilityPlan',
    'Test-GsaClientEvidence',
    'Test-GsaObservabilityEvidence'
)
