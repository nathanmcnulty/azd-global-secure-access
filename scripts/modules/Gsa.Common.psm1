Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-GsaBoolean {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,
        [bool]$Default = $false
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $Default
    }
    if ($Value -is [bool]) {
        return $Value
    }

    switch ([string]$Value.Trim().ToLowerInvariant()) {
        { $_ -in '1', 'true', 'yes', 'on', 'enabled' } { return $true }
        { $_ -in '0', 'false', 'no', 'off', 'disabled' } { return $false }
        default { throw "Value '$Value' is not a valid boolean." }
    }
}

function Get-GsaList {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,
        [string]$Separator = ','
    )

    if ($null -eq $Value) {
        return [string[]]@()
    }

    $items = if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        @($Value)
    } else {
        @([string]$Value -split [regex]::Escape($Separator))
    }

    return [string[]]@(
        $items |
            ForEach-Object { [string]$_ } |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Select-Object -Unique
    )
}

function Get-GsaEnvironmentValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [AllowNull()]
        [string]$Default,
        [switch]$Required
    )

    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = $Default
    }
    if ($Required -and [string]::IsNullOrWhiteSpace($value)) {
        throw "Required azd environment value '$Name' is not set."
    }
    return $value
}

function Assert-GsaPreviewGate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Feature,
        [bool]$Enabled
    )

    if (-not $Enabled) {
        return
    }

    $accepted = Get-GsaBoolean -Value $env:GSA_ACCEPT_GRAPH_BETA_TERMS
    if (-not $accepted) {
        throw "$Feature uses Microsoft Graph beta. Set GSA_ACCEPT_GRAPH_BETA_TERMS=true after reviewing the documented preview limitations."
    }
}

function Get-GsaPlainTextToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceUrl
    )

    $token = (Get-AzAccessToken -ResourceUrl $ResourceUrl).Token
    if ($token -is [System.Security.SecureString]) {
        return $token | ConvertFrom-SecureString -AsPlainText
    }
    return [string]$token
}

function Connect-GsaGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Scopes,
        [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
        [string]$Environment = 'Global'
    )

    $context = Get-MgContext -ErrorAction SilentlyContinue
    if ($context -and $context.Environment -ne $Environment) {
        throw "Microsoft Graph is connected to '$($context.Environment)' but '$Environment' is required for this environment."
    }
    $missing = if ($context) {
        @($Scopes | Where-Object { $_ -notin $context.Scopes })
    } else {
        @($Scopes)
    }

    if (-not $context -or $missing.Count -gt 0) {
        Connect-MgGraph -Scopes $Scopes -Environment $Environment -NoWelcome | Out-Null
        $context = Get-MgContext
    }

    if ($context.Environment -ne $Environment) {
        throw "Microsoft Graph connected to '$($context.Environment)' instead of '$Environment'."
    }
    $missing = @($Scopes | Where-Object { $_ -notin $context.Scopes })
    if ($missing.Count -gt 0) {
        throw "Microsoft Graph consent is missing: $($missing -join ', ')."
    }
    return $context
}

function Get-GsaGraphEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
        [string]$Environment
    )

    switch ($Environment) {
        'Global' { return 'https://graph.microsoft.com' }
        'USGov' { return 'https://graph.microsoft.us' }
        'USGovDoD' { return 'https://dod-graph.microsoft.us' }
        'China' { return 'https://microsoftgraph.chinacloudapi.cn' }
    }
}

function Get-GsaCloudCapability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AzureCloud,
        [string]$GraphEnvironment
    )

    $definition = switch ($AzureCloud) {
        'AzureCloud' {
            [ordered]@{
                ExpectedGraphEnvironments = @('Global')
                ArmEndpoint               = 'https://management.azure.com/'
                GraphCoreRead             = $true
                ForwardingRules           = $true
                ForwardingMutation        = $true
                TenantOnboarding          = $true
                Licensing                 = $true
                Settings                  = $true
                DeploymentLogs            = $true
                Tls                       = $true
                Filtering                 = $true
                GraphMutation             = $true
                AzureDataPlane            = $true
                Evidence                  = 'Global Microsoft Graph networkAccess APIs and the template Azure data-plane endpoints are supported.'
            }
        }
        'AzureUSGovernment' {
            [ordered]@{
                ExpectedGraphEnvironments = @('USGov', 'USGovDoD')
                ArmEndpoint               = 'https://management.usgovcloudapi.net/'
                GraphCoreRead             = $true
                ForwardingRules           = $true
                ForwardingMutation        = $true
                TenantOnboarding          = $true
                Licensing                 = $true
                Settings                  = $false
                DeploymentLogs            = $false
                Tls                       = $false
                Filtering                 = $false
                GraphMutation             = $false
                AzureDataPlane            = $false
                Evidence                  = 'Forwarding profiles, forwarding policies, and policy rules document US Government L4/L5 support. TLS certificate APIs document global-only support, and the remaining template mutation/data-plane surfaces are not validated for this cloud.'
            }
        }
        'AzureChinaCloud' {
            [ordered]@{
                ExpectedGraphEnvironments = @('China')
                ArmEndpoint               = 'https://management.chinacloudapi.cn/'
                GraphCoreRead             = $false
                ForwardingRules           = $false
                ForwardingMutation        = $false
                TenantOnboarding          = $false
                Licensing                 = $true
                Settings                  = $false
                DeploymentLogs            = $false
                Tls                       = $false
                Filtering                 = $false
                GraphMutation             = $false
                AzureDataPlane            = $false
                Evidence                  = 'Subscribed SKU reads support China, but the required networkAccess forwarding and TLS APIs explicitly do not.'
            }
        }
        default {
            [ordered]@{
                ExpectedGraphEnvironments = @()
                ArmEndpoint               = $null
                GraphCoreRead             = $false
                ForwardingRules           = $false
                ForwardingMutation        = $false
                TenantOnboarding          = $false
                Licensing                 = $false
                Settings                  = $false
                DeploymentLogs            = $false
                Tls                       = $false
                Filtering                 = $false
                GraphMutation             = $false
                AzureDataPlane            = $false
                Evidence                  = "Azure cloud '$AzureCloud' is not in the validated capability matrix."
            }
        }
    }

    $environmentMatch = -not $GraphEnvironment -or $GraphEnvironment -in $definition.ExpectedGraphEnvironments
    return [pscustomobject]@{
        AzureCloud                = $AzureCloud
        GraphEnvironment          = $GraphEnvironment
        ExpectedGraphEnvironments = [string[]]$definition.ExpectedGraphEnvironments
        ArmEndpoint               = $definition.ArmEndpoint
        GraphCoreRead             = $definition.GraphCoreRead -and $environmentMatch
        ForwardingRules           = $definition.ForwardingRules -and $environmentMatch
        ForwardingMutation        = $definition.ForwardingMutation -and $environmentMatch
        TenantOnboarding          = $definition.TenantOnboarding -and $environmentMatch
        Licensing                 = $definition.Licensing -and $environmentMatch
        Settings                  = $definition.Settings -and $environmentMatch
        DeploymentLogs            = $definition.DeploymentLogs -and $environmentMatch
        Tls                       = $definition.Tls -and $environmentMatch
        Filtering                 = $definition.Filtering -and $environmentMatch
        GraphMutation             = $definition.GraphMutation -and $environmentMatch
        AzureDataPlane            = $definition.AzureDataPlane
        EnvironmentMatch          = $environmentMatch
        Evidence                  = $definition.Evidence
    }
}

function Assert-GsaCloudCapability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Capability,
        [Parameter(Mandatory)]
        [ValidateSet(
            'GraphCoreRead',
            'ForwardingRules',
            'ForwardingMutation',
            'TenantOnboarding',
            'Licensing',
            'Settings',
            'DeploymentLogs',
            'Tls',
            'Filtering',
            'GraphMutation',
            'AzureDataPlane'
        )]
        [string]$Surface
    )

    if (-not $Capability.$Surface) {
        $expected = if ($Capability.ExpectedGraphEnvironments.Count -gt 0) {
            " Expected Graph environment: $($Capability.ExpectedGraphEnvironments -join ' or ')."
        } else {
            ''
        }
        throw "Surface '$Surface' is unsupported for Azure cloud '$($Capability.AzureCloud)' and Graph environment '$($Capability.GraphEnvironment)'.$expected $($Capability.Evidence)"
    }
}

function Get-GsaGraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [hashtable]$Headers
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    while ($nextUri) {
        $parameters = @{
            Method     = 'GET'
            Uri        = $nextUri
            OutputType = 'PSObject'
        }
        if ($Headers) {
            $parameters.Headers = $Headers
        }

        $response = Invoke-MgGraphRequest @parameters
        if ($response.PSObject.Properties['value']) {
            foreach ($item in @($response.value)) {
                $items.Add($item)
            }
            $nextUri = if ($response.PSObject.Properties['@odata.nextLink']) {
                $response.'@odata.nextLink'
            } else {
                $null
            }
        } else {
            $items.Add($response)
            $nextUri = $null
        }
    }
    return $items.ToArray()
}

function ConvertTo-GsaNormalizedPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Value
    )

    $ports = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $Value) {
        foreach ($candidate in ([string]$entry -split ',')) {
            $candidate = $candidate.Trim()
            if (-not $candidate) {
                continue
            }
            $match = [regex]::Match($candidate, '^(?<start>\d{1,5})(?:\s*-\s*(?<end>\d{1,5}))?$')
            if (-not $match.Success) {
                throw "Port '$candidate' must be a single port or an ascending range."
            }
            $start = [int]$match.Groups['start'].Value
            $end = if ($match.Groups['end'].Success) { [int]$match.Groups['end'].Value } else { $start }
            if ($start -lt 1 -or $end -gt 65535 -or $start -gt $end) {
                throw "Port '$candidate' is outside 1-65535 or is not ascending."
            }
            $normalized = "$start-$end"
            if (-not $ports.Contains($normalized)) {
                $ports.Add($normalized)
            }
        }
    }
    if ($ports.Count -eq 0) {
        throw 'At least one port is required.'
    }
    return [string[]]@($ports | Sort-Object)
}

function Get-GsaNetworkAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.IPAddress]$Address,
        [Parameter(Mandatory)]
        [int]$PrefixLength
    )

    $bytes = $Address.GetAddressBytes()
    $result = [byte[]]::new($bytes.Length)
    $remaining = $PrefixLength
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        if ($remaining -ge 8) {
            $result[$index] = $bytes[$index]
            $remaining -= 8
        } elseif ($remaining -gt 0) {
            $mask = [byte]((0xff -shl (8 - $remaining)) -band 0xff)
            $result[$index] = [byte]($bytes[$index] -band $mask)
            $remaining = 0
        }
    }
    return [System.Net.IPAddress]::new($result)
}

function Get-GsaNormalizedDestination {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $parts = $Value.Trim().Split(':', 2)
    if ($parts.Count -ne 2) {
        throw "Destination '$Value' must use type:value syntax."
    }
    $type = $parts[0].Trim().ToLowerInvariant()
    $hostValue = $parts[1].Trim().ToLowerInvariant()
    if (-not $hostValue) {
        throw "Destination '$Value' has no value."
    }

    switch ($type) {
        'fqdn' {
            if ($hostValue -notmatch '^[a-z0-9*][a-z0-9.*-]+$') {
                throw "FQDN '$hostValue' is invalid."
            }
            return [pscustomobject]@{ Type = 'fqdn'; Host = $hostValue }
        }
        'dnssuffix' {
            return [pscustomobject]@{ Type = 'dnsSuffix'; Host = $hostValue.TrimStart('.') }
        }
        { $_ -in 'ip', 'ipaddress', 'iprangecidr' } {
            $addressText, $prefixText = $hostValue.Split('/', 2)
            $address = $null
            if (-not [System.Net.IPAddress]::TryParse($addressText, [ref]$address)) {
                throw "IP destination '$hostValue' is invalid."
            }
            $maximum = if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { 128 } else { 32 }
            $prefix = if ($prefixText) { [int]$prefixText } else { $maximum }
            if ($prefix -lt 0 -or $prefix -gt $maximum) {
                throw "IP prefix '$prefix' is invalid for '$addressText'."
            }
            $network = Get-GsaNetworkAddress -Address $address -PrefixLength $prefix
            return [pscustomobject]@{
                Type = 'ipRangeCidr'
                Host = "$($network.IPAddressToString)/$prefix"
            }
        }
        default { throw "Destination type '$type' is not supported. Use fqdn, dnsSuffix, or ip." }
    }
}

function Get-GsaSegmentKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DestinationType,
        [Parameter(Mandatory)]
        [string]$DestinationHost,
        [Parameter(Mandatory)]
        [string[]]$Ports,
        [Parameter(Mandatory)]
        [string]$Protocol
    )

    $destination = Get-GsaNormalizedDestination -Value "$DestinationType`:$DestinationHost"
    $normalizedPorts = ConvertTo-GsaNormalizedPort -Value $Ports
    return "$($destination.Type.ToLowerInvariant())|$($destination.Host)|$($Protocol.ToLowerInvariant())|$($normalizedPorts -join ',')"
}

Export-ModuleMember -Function @(
    'Assert-GsaPreviewGate',
    'Assert-GsaCloudCapability',
    'Connect-GsaGraph',
    'Get-GsaBoolean',
    'Get-GsaCloudCapability',
    'Get-GsaEnvironmentValue',
    'Get-GsaGraphEndpoint',
    'Get-GsaGraphCollection',
    'Get-GsaList',
    'Get-GsaNetworkAddress',
    'Get-GsaNormalizedDestination',
    'ConvertTo-GsaNormalizedPort',
    'Get-GsaPlainTextToken',
    'Get-GsaSegmentKey'
)
