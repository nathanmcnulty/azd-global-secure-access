Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:GsaManifestSchemaVersion = '1.0.0'
$script:GsaManifestFileName = 'gsa-state.json'
$script:GsaPendingFileName = 'gsa-state.pending.json'

function ConvertTo-GsaCanonicalValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [string] -or $Value -is [ValueType]) {
        return $Value
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object)) {
            $result[$key] = ConvertTo-GsaCanonicalValue -Value $Value[$key]
        }
        return $result
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        [object[]]$items = @($Value | ForEach-Object { ConvertTo-GsaCanonicalValue -Value $_ })
        Write-Output -InputObject $items -NoEnumerate
        return
    }

    $properties = @($Value.PSObject.Properties | Where-Object MemberType -in NoteProperty, Property | Sort-Object Name)
    if ($properties.Count -eq 0) {
        return [string]$Value
    }
    $result = [ordered]@{}
    foreach ($property in $properties) {
        $result[$property.Name] = ConvertTo-GsaCanonicalValue -Value $property.Value
    }
    return $result
}

function Get-GsaStateFingerprint {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    $canonical = ConvertTo-GsaCanonicalValue -Value $Value
    $json = $canonical | ConvertTo-Json -Depth 100 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Get-GsaStatePath {
    [CmdletBinding()]
    param(
        [string]$ProjectRoot,
        [string]$EnvironmentName = $env:AZURE_ENV_NAME,
        [switch]$Pending
    )

    if ([string]::IsNullOrWhiteSpace($EnvironmentName)) {
        throw 'AZURE_ENV_NAME is required to resolve the GSA state manifest.'
    }
    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
        $ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    }
    $fileName = if ($Pending) { $script:GsaPendingFileName } else { $script:GsaManifestFileName }
    return Join-Path (Join-Path (Join-Path $ProjectRoot '.azure') $EnvironmentName) $fileName
}

function Assert-GsaStateContentSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Value
    )

    $forbiddenNames = '(?i)(access.?token|refresh.?token|client.?secret|private.?key|pre.?shared.?key|(^|_)psk($|_))'
    $forbiddenValues = '(?i)-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----|^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.'

    function Test-Value {
        param([AllowNull()][object]$InputValue, [string]$Path)

        if ($null -eq $InputValue) {
            return
        }
        if ($InputValue -is [System.Collections.IDictionary]) {
            foreach ($key in $InputValue.Keys) {
                $name = [string]$key
                if ($name -match $forbiddenNames) {
                    throw "State content '$Path.$name' is forbidden because manifests must not contain secrets or private material."
                }
                Test-Value -InputValue $InputValue[$key] -Path "$Path.$name"
            }
            return
        }
        if ($InputValue -is [System.Collections.IEnumerable] -and $InputValue -isnot [string]) {
            $index = 0
            foreach ($item in $InputValue) {
                Test-Value -InputValue $item -Path "$Path[$index]"
                $index++
            }
            return
        }
        if ($InputValue -isnot [string] -and $InputValue -isnot [ValueType]) {
            foreach ($property in $InputValue.PSObject.Properties | Where-Object MemberType -in NoteProperty, Property) {
                if ($property.Name -match $forbiddenNames) {
                    throw "State content '$Path.$($property.Name)' is forbidden because manifests must not contain secrets or private material."
                }
                Test-Value -InputValue $property.Value -Path "$Path.$($property.Name)"
            }
            return
        }
        if ([string]$InputValue -match $forbiddenValues) {
            throw "State content '$Path' appears to contain an access token or private key."
        }
    }

    Test-Value -InputValue $Value -Path '$'
}

function Write-GsaAtomicJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [object]$Value
    )

    Assert-GsaStateContentSafe -Value $Value
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $parent = Split-Path $resolved -Parent
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $temporaryPath = Join-Path $parent ".$([IO.Path]::GetFileName($resolved)).$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $canonical = ConvertTo-GsaCanonicalValue -Value $Value
        $json = $canonical | ConvertTo-Json -Depth 100
        [IO.File]::WriteAllText($temporaryPath, "$json`n", [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporaryPath, $resolved, $true)
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Read-GsaStateManifest {
    [CmdletBinding()]
    param(
        [string]$Path = (Get-GsaStatePath)
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    $manifest = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100
    if ($manifest.schemaVersion -ne $script:GsaManifestSchemaVersion) {
        throw "State manifest '$Path' uses schema '$($manifest.schemaVersion)'; expected '$script:GsaManifestSchemaVersion'."
    }
    Assert-GsaStateContentSafe -Value $manifest
    return $manifest
}

function Write-GsaPendingTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Environment,
        [Parameter(Mandatory)]
        [object]$DesiredState,
        [string]$Path = (Get-GsaStatePath -Pending),
        [DateTimeOffset]$StartedAt = [DateTimeOffset]::UtcNow
    )

    $transaction = [ordered]@{
        schemaVersion           = $script:GsaManifestSchemaVersion
        status                  = 'pending'
        operationId             = [guid]::NewGuid().ToString()
        startedAt               = $StartedAt.ToUniversalTime().ToString('O')
        environment             = ConvertTo-GsaCanonicalValue -Value $Environment
        desiredStateFingerprint = Get-GsaStateFingerprint -Value $DesiredState
    }
    Write-GsaAtomicJson -Path $Path -Value $transaction
    return [pscustomobject]$transaction
}

function ConvertTo-GsaStateResource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Kind,
        [AllowNull()][string]$Id,
        [Parameter(Mandatory)][object]$NaturalId,
        [Parameter(Mandatory)][object]$DesiredState,
        [AllowNull()][object]$ObservedState,
        [AllowNull()][object]$PreviousMutableState,
        [AllowNull()][string]$ReadUri,
        [bool]$Created,
        [ValidateSet('managed', 'reused')]
        [string]$Ownership,
        [ValidateSet('created', 'reused', 'declared')]
        [string]$Provenance,
        [ValidateSet('active', 'retired')]
        [string]$LifecycleState,
        [AllowNull()][object]$PreviousManifest
    )

    $previous = if ($PreviousManifest -and $PreviousManifest.PSObject.Properties['resources']) {
        @($PreviousManifest.resources | Where-Object { $_.key -eq $Key -and $_.id -eq $Id }) | Select-Object -First 1
    } else {
        $null
    }
    $previouslyManaged = $previous -and $previous.ownership -eq 'managed'
    $resolvedOwnership = if ($Ownership) { $Ownership } elseif ($Created -or $previouslyManaged) { 'managed' } else { 'reused' }
    $resolvedProvenance = if ($Provenance) { $Provenance } elseif ($Created) { 'created' } else { 'reused' }
    $resolvedLifecycleState = if ($LifecycleState) {
        $LifecycleState
    } elseif ($previous -and $previous.PSObject.Properties['lifecycleState']) {
        $previous.lifecycleState
    } else {
        'active'
    }
    $restoreState = if ($previous -and $previous.PSObject.Properties['previousMutableState']) {
        $previous.previousMutableState
    } else {
        $PreviousMutableState
    }

    return [pscustomobject][ordered]@{
        key                  = $Key
        kind                 = $Kind
        id                   = $Id
        naturalId            = ConvertTo-GsaCanonicalValue -Value $NaturalId
        ownership            = $resolvedOwnership
        provenance           = $resolvedProvenance
        lifecycleState       = $resolvedLifecycleState
        desiredState         = ConvertTo-GsaCanonicalValue -Value $DesiredState
        desiredFingerprint   = Get-GsaProjectedFingerprint -Actual $DesiredState -Desired $DesiredState
        observedState        = ConvertTo-GsaCanonicalValue -Value $ObservedState
        observedFingerprint  = Get-GsaStateFingerprint -Value $ObservedState
        previousMutableState = ConvertTo-GsaCanonicalValue -Value $restoreState
        readUri              = $ReadUri
    }
}

function ConvertTo-GsaStateManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Environment,
        [Parameter(Mandatory)][object]$DesiredState,
        [Parameter(Mandatory)][object[]]$Resources,
        [Parameter(Mandatory)][string]$OperationId,
        [DateTimeOffset]$CompletedAt = [DateTimeOffset]::UtcNow
    )

    return [pscustomobject][ordered]@{
        schemaVersion = $script:GsaManifestSchemaVersion
        contracts     = [ordered]@{
            template             = '0.2.0'
            microsoftGraph       = 'beta@2026-08'
            microsoftGraphStable = 'v1.0@2026-08'
            keyVault             = '7.5'
            storage              = '2023-11-03'
            azd                  = '>=1.30.0'
        }
        environment   = ConvertTo-GsaCanonicalValue -Value $Environment
        desiredState = [ordered]@{
            fingerprint   = Get-GsaStateFingerprint -Value $DesiredState
            configuration = ConvertTo-GsaCanonicalValue -Value $DesiredState
        }
        resources    = @($Resources | Sort-Object key | ForEach-Object { ConvertTo-GsaCanonicalValue -Value $_ })
        operation    = [ordered]@{
            id          = $OperationId
            status      = 'committed'
            completedAt = $CompletedAt.ToUniversalTime().ToString('O')
        }
    }
}

function Merge-GsaStateResourceSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$CurrentResources,
        [AllowNull()][object]$PreviousManifest
    )

    $resourcesByKey = [ordered]@{}
    if ($PreviousManifest -and $PreviousManifest.PSObject.Properties['resources']) {
        foreach ($resource in @($PreviousManifest.resources | Sort-Object key)) {
            $resourcesByKey[[string]$resource.key] = $resource
        }
    }
    foreach ($resource in @($CurrentResources | Sort-Object key)) {
        $resourcesByKey[[string]$resource.key] = $resource
    }
    return @($resourcesByKey.Values | Sort-Object key)
}

function Complete-GsaStateTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Transaction,
        [Parameter(Mandatory)][object]$Manifest,
        [string]$ManifestPath = (Get-GsaStatePath),
        [string]$PendingPath = (Get-GsaStatePath -Pending)
    )

    if ($Transaction.status -ne 'pending' -or $Manifest.operation.id -ne $Transaction.operationId) {
        throw 'The committed manifest does not match the active pending transaction.'
    }
    if ($Manifest.desiredState.fingerprint -ne $Transaction.desiredStateFingerprint) {
        throw 'The committed manifest desired state does not match the pending transaction.'
    }
    Write-GsaAtomicJson -Path $ManifestPath -Value $Manifest
    if (Test-Path -LiteralPath $PendingPath) {
        Remove-Item -LiteralPath $PendingPath -Force
    }
}

function Get-GsaProjectedStateString {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Desired,
        [switch]$DesiredIsArray
    )

    if ($DesiredIsArray) {
        $desiredItems = @($Desired)
        $actualItems = @($Actual)
        if ($desiredItems.Count -eq 0) {
            return if ($actualItems.Count -eq 0) { '[]' } else { "[`"__unexpected_count:$($actualItems.Count)`"]" }
        }
        $template = $desiredItems[0]
        $projectedItems = @(
            $actualItems | ForEach-Object {
                Get-GsaProjectedStateString -Actual $_ -Desired $template
            } | Sort-Object
        )
        return "[$($projectedItems -join ',')]"
    }
    if ($null -eq $Desired) {
        return 'null'
    }
    if ($Desired -is [string] -or $Desired -is [ValueType]) {
        return ConvertTo-Json -InputObject $Actual -Depth 100 -Compress
    }

    $desiredProperties = if ($Desired -is [System.Collections.IDictionary]) {
        @($Desired.Keys | ForEach-Object { [string]$_ })
    } else {
        @($Desired.PSObject.Properties.Name)
    }
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $desiredProperties | Sort-Object) {
        $desiredValue = if ($Desired -is [System.Collections.IDictionary]) { $Desired[$name] } else { $Desired.$name }
        $actualValue = if ($Actual -is [System.Collections.IDictionary]) {
            if ($Actual.Contains($name)) { $Actual[$name] } else { $null }
        } elseif ($Actual -and $Actual.PSObject.Properties[$name]) {
            $Actual.$name
        } else {
            $null
        }
        $isArray = $desiredValue -is [System.Collections.IEnumerable] -and
            $desiredValue -isnot [string] -and
            $desiredValue -isnot [System.Collections.IDictionary]
        $projectedValue = Get-GsaProjectedStateString -Actual $actualValue -Desired $desiredValue -DesiredIsArray:$isArray
        $encodedName = ConvertTo-Json -InputObject $name -Compress
        $parts.Add("$encodedName`:$projectedValue")
    }
    return "{$($parts -join ',')}"
}

function Get-GsaProjectedFingerprint {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Actual,
        [Parameter(Mandatory)][object]$Desired
    )

    $isArray = $Desired -is [System.Collections.IEnumerable] -and
        $Desired -isnot [string] -and
        $Desired -isnot [System.Collections.IDictionary]
    $projected = Get-GsaProjectedStateString -Actual $Actual -Desired $Desired -DesiredIsArray:$isArray
    $bytes = [Text.Encoding]::UTF8.GetBytes($projected)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Compare-GsaResourceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Resource,
        [AllowNull()][object]$Actual,
        [AllowNull()][string]$ActualId
    )

    if ($null -eq $Actual) {
        return 'missing'
    }
    if ($Resource.id -and $ActualId -and $Resource.id -ne $ActualId) {
        return 'unmanagedConflict'
    }
    $status = if ($Actual.PSObject.Properties['status']) { [string]$Actual.status } elseif ($Actual.PSObject.Properties['state']) { [string]$Actual.state } else { $null }
    if ($status -and $status -notin 'active', 'enabled', 'disabled', 'succeeded', 'onboarded', 'offboarded') {
        return 'unknownTransitional'
    }
    if ((Get-GsaProjectedFingerprint -Actual $Actual -Desired $Resource.desiredState) -ne $Resource.desiredFingerprint) {
        return 'changed'
    }
    if ($Resource.ownership -eq 'managed') {
        return 'managed'
    }
    return 'reused'
}

Export-ModuleMember -Function @(
    'Assert-GsaStateContentSafe',
    'Compare-GsaResourceState',
    'Complete-GsaStateTransaction',
    'ConvertTo-GsaCanonicalValue',
    'Get-GsaProjectedFingerprint',
    'Get-GsaStateFingerprint',
    'Get-GsaStatePath',
    'Merge-GsaStateResourceSet',
    'ConvertTo-GsaStateManifest',
    'ConvertTo-GsaStateResource',
    'Read-GsaStateManifest',
    'Write-GsaPendingTransaction',
    'Write-GsaAtomicJson'
)
