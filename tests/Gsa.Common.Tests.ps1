BeforeAll {
    function global:Get-MgContext { [CmdletBinding()] param() }
    function global:Invoke-MgGraphRequest {
        [CmdletBinding()]
        param(
            [string]$Method,
            [string]$Uri,
            [string]$OutputType,
            [hashtable]$Headers,
            [object]$Body,
            [string]$ContentType
        )
    }
    Import-Module (Join-Path $PSScriptRoot '..\scripts\modules\Gsa.Common.psm1') -Force
}

AfterAll {
    Remove-Item Function:\global:Get-MgContext -ErrorAction SilentlyContinue
    Remove-Item Function:\global:Invoke-MgGraphRequest -ErrorAction SilentlyContinue
}

Describe 'GSA parameter normalization' {
    It 'normalizes booleans without treating arbitrary text as true' {
        Get-GsaBoolean 'enabled' | Should -BeTrue
        Get-GsaBoolean '0' | Should -BeFalse
        { Get-GsaBoolean 'perhaps' } | Should -Throw '*not a valid boolean*'
    }

    It 'normalizes and deduplicates ports' {
        $ports = ConvertTo-GsaNormalizedPort -Value @('443', '3389-3390', '443-443')
        $ports | Should -Be @('3389-3390', '443-443')
    }

    It 'rejects invalid or descending ports' {
        { ConvertTo-GsaNormalizedPort -Value @('0') } | Should -Throw
        { ConvertTo-GsaNormalizedPort -Value @('444-443') } | Should -Throw
        { ConvertTo-GsaNormalizedPort -Value @('https') } | Should -Throw
    }

    It 'canonicalizes host IPs and CIDR networks' {
        $hostAddress = Get-GsaNormalizedDestination -Value 'ip:10.2.2.174'
        $hostAddress.Type | Should -Be 'ipRangeCidr'
        $hostAddress.Host | Should -Be '10.2.2.174/32'

        $network = Get-GsaNormalizedDestination -Value 'ip:10.2.2.174/24'
        $network.Host | Should -Be '10.2.2.0/24'
    }

    It 'creates stable idempotency keys' {
        $first = Get-GsaSegmentKey -DestinationType ipRangeCidr -DestinationHost '10.2.2.174/32' -Ports @('443') -Protocol TCP
        $second = Get-GsaSegmentKey -DestinationType ip -DestinationHost '10.2.2.174' -Ports @('443-443') -Protocol tcp
        $first | Should -Be $second
    }

    It 'normalizes DNS suffix and FQDN destinations' {
        (Get-GsaNormalizedDestination 'dnsSuffix:.contoso.local').Host | Should -Be 'contoso.local'
        (Get-GsaNormalizedDestination 'fqdn:App.Contoso.Local').Host | Should -Be 'app.contoso.local'
    }

    It 'handles a single Graph collection page without a nextLink property' {
        Mock -ModuleName Gsa.Common Get-MgContext {
            [pscustomobject]@{ Environment = 'Global' }
        }
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest {
            [pscustomobject]@{
                value = @([pscustomobject]@{ id = 'one' })
            }
        }

        $items = @(Get-GsaGraphCollection -Uri '/beta/example')
        $items | Should -HaveCount 1
        $items[0].id | Should -Be 'one'
    }
}

Describe 'Bounded Microsoft Graph collection pagination' {
    BeforeEach {
        Mock -ModuleName Gsa.Common Get-MgContext {
            [pscustomobject]@{ Environment = 'Global' }
        }
    }

    It 'handles empty, single-item, and multi-item pages' {
        $script:pageNumber = 0
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest {
            $script:pageNumber++
            switch ($script:pageNumber) {
                1 {
                    [pscustomobject]@{
                        value = @()
                        '@odata.nextLink' = 'https://graph.microsoft.com/beta/example?$skiptoken=one'
                    }
                }
                2 {
                    [pscustomobject]@{
                        value = @([pscustomobject]@{ id = 'one' })
                        '@odata.nextLink' = '/beta/example?$skiptoken=two'
                    }
                }
                default {
                    [pscustomobject]@{
                        value = @(
                            [pscustomobject]@{ id = 'two' },
                            [pscustomobject]@{ id = 'three' }
                        )
                    }
                }
            }
        }

        $items = @(Get-GsaGraphCollection -Uri '/beta/example')
        $items.id | Should -Be @('one', 'two', 'three')
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 3 -Exactly
    }

    It 'preserves an opaque continuation and caller headers on every page' {
        $continuation = 'https://graph.microsoft.com/beta/example?$skiptoken=opaque%2Btoken%3D%3D&x=a+b'
        $headers = @{ Prefer = 'include-unknown-enum-members' }
        $script:requests = [System.Collections.Generic.List[object]]::new()
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest {
            $script:requests.Add([pscustomobject]@{ Uri = $Uri; Headers = $Headers })
            if ($script:requests.Count -eq 1) {
                return [pscustomobject]@{ value = @(); '@odata.nextLink' = $continuation }
            }
            return [pscustomobject]@{ value = @() }
        }

        @(Get-GsaGraphCollection -Uri '/beta/example?first=a%2Bb' -Headers $headers) | Should -HaveCount 0
        $script:requests.Uri | Should -Be @('/beta/example?first=a%2Bb', $continuation)
        [object]::ReferenceEquals($script:requests[0].Headers, $headers) | Should -BeTrue
        [object]::ReferenceEquals($script:requests[1].Headers, $headers) | Should -BeTrue
    }

    It 'accepts the exact endpoint for each supported Graph environment' -TestCases @(
        @{ Environment = 'Global'; Endpoint = 'https://graph.microsoft.com' }
        @{ Environment = 'USGov'; Endpoint = 'https://graph.microsoft.us' }
        @{ Environment = 'USGovDoD'; Endpoint = 'https://dod-graph.microsoft.us' }
        @{ Environment = 'China'; Endpoint = 'https://microsoftgraph.chinacloudapi.cn' }
    ) {
        param($Environment, $Endpoint)

        Mock -ModuleName Gsa.Common Get-MgContext {
            [pscustomobject]@{ Environment = $Environment }
        }
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest {
            [pscustomobject]@{ value = @() }
        }

        @(Get-GsaGraphCollection -Uri "$Endpoint/v1.0/example") | Should -HaveCount 0
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 1 -Exactly
    }

    It 'rejects a missing or unknown session environment before dispatch' -TestCases @(
        @{ Context = $null }
        @{ Context = [pscustomobject]@{} }
        @{ Context = [pscustomobject]@{ Environment = 'UnknownCloud' } }
    ) {
        param($Context)

        Mock -ModuleName Gsa.Common Get-MgContext { $Context }
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest { throw 'must not dispatch' }

        { Get-GsaGraphCollection -Uri '/beta/example' } |
            Should -Throw -ExpectedMessage 'Graph collection pagination validation failed.'
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'rejects invalid initial locations before dispatch' -TestCases @(
        @{ Candidate = 'beta/example' }
        @{ Candidate = '//evil.example/beta/example' }
        @{ Candidate = '/beta\example' }
        @{ Candidate = "https://graph.microsoft.com/beta/example`n" }
        @{ Candidate = 'http://graph.microsoft.com/beta/example' }
        @{ Candidate = 'https://user:secret@graph.microsoft.com/beta/example' }
        @{ Candidate = 'https://graph.microsoft.com:444/beta/example' }
        @{ Candidate = 'https://graph.microsoft.com/beta/example#fragment' }
        @{ Candidate = 'https://graph.microsoft.us/beta/example' }
    ) {
        param($Candidate)

        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest { throw 'must not dispatch' }
        { Get-GsaGraphCollection -Uri $Candidate } |
            Should -Throw -ExpectedMessage 'Graph collection pagination validation failed.'
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'rejects an invalid continuation without dispatching it' -TestCases @(
        @{ NextLink = 'https://evil.example/beta/example?$skiptoken=secret' }
        @{ NextLink = 'https://graph.microsoft.com/v1.0/other?$skiptoken=secret' }
        @{ NextLink = 'https://graph.microsoft.com:444/beta/example' }
        @{ NextLink = 'http://graph.microsoft.com/beta/example' }
        @{ NextLink = 'https://user:secret@graph.microsoft.com/beta/example' }
        @{ NextLink = 'https://graph.microsoft.com/beta/example#fragment' }
        @{ NextLink = '//evil.example/beta/example' }
        @{ NextLink = '/beta\example' }
        @{ NextLink = "https://graph.microsoft.com/beta/example`r`nX-Test: value" }
        @{ NextLink = 'not a URI' }
        @{ NextLink = '' }
    ) {
        param($NextLink)

        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest {
            [pscustomobject]@{ value = @([pscustomobject]@{ id = 'buffered' }); '@odata.nextLink' = $NextLink }
        }
        $emitted = @()
        try { $emitted = @(Get-GsaGraphCollection -Uri '/beta/example') } catch { $caught = $_ }

        $caught.Exception.Message | Should -Be 'Graph collection pagination validation failed.'
        $emitted | Should -HaveCount 0
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 1 -Exactly
    }

    It 'rejects a non-string continuation without another dispatch' {
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest {
            [pscustomobject]@{ value = @(); '@odata.nextLink' = [pscustomobject]@{ uri = 'https://graph.microsoft.com/beta/example' } }
        }

        { Get-GsaGraphCollection -Uri '/beta/example' } |
            Should -Throw -ExpectedMessage 'Graph collection pagination validation failed.'
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 1 -Exactly
    }

    It 'detects a cycle before dispatching the repeated page and emits no partial items' {
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest {
            [pscustomobject]@{
                value = @([pscustomobject]@{ id = 'buffered' })
                '@odata.nextLink' = 'https://graph.microsoft.com/beta/example'
            }
        }
        $emitted = @()
        try { $emitted = @(Get-GsaGraphCollection -Uri '/beta/example') } catch { $caught = $_ }

        $caught.Exception.Message | Should -Be 'Graph collection pagination validation failed.'
        $emitted | Should -HaveCount 0
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 1 -Exactly
    }

    It 'enforces a page bound before dispatching an excess page and emits no partial items' {
        $script:pageNumber = 0
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest {
            $script:pageNumber++
            [pscustomobject]@{
                value = @([pscustomobject]@{ id = $script:pageNumber })
                '@odata.nextLink' = "https://graph.microsoft.com/beta/example?`$skiptoken=$script:pageNumber"
            }
        }
        $emitted = @()
        try { $emitted = @(Get-GsaGraphCollection -Uri '/beta/example' -MaximumPages 2) } catch { $caught = $_ }

        $caught.Exception.Message | Should -Be 'Graph collection pagination validation failed.'
        $emitted | Should -HaveCount 0
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 2 -Exactly
    }

    It 'enforces an item bound without returning a partial collection' {
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest {
            [pscustomobject]@{
                value = @(
                    [pscustomobject]@{ id = 'one' },
                    [pscustomobject]@{ id = 'two' },
                    [pscustomobject]@{ id = 'three' }
                )
            }
        }
        $emitted = @()
        try { $emitted = @(Get-GsaGraphCollection -Uri '/beta/example' -MaximumItems 2) } catch { $caught = $_ }

        $caught.Exception.Message | Should -Be 'Graph collection pagination validation failed.'
        $emitted | Should -HaveCount 0
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 1 -Exactly
    }

    It 'rejects a non-collection response shape' {
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest {
            [pscustomobject]@{ id = 'single-object' }
        }

        { Get-GsaGraphCollection -Uri '/beta/example' } |
            Should -Throw -ExpectedMessage 'Graph collection pagination validation failed.'
    }

    It 'rejects a malformed value collection without another dispatch or partial output' -TestCases @(
        @{ Value = $null; Label = 'null' }
        @{ Value = 'not-a-collection'; Label = 'string' }
        @{ Value = 42; Label = 'number' }
        @{ Value = [pscustomobject]@{ id = 'single-object' }; Label = 'single object' }
        @{ Value = @{ id = 'dictionary' }; Label = 'dictionary' }
    ) {
        param($Value, $Label)

        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest {
            [pscustomobject]@{
                value = $Value
                '@odata.nextLink' = 'https://graph.microsoft.com/beta/example?$skiptoken=must-not-dispatch'
            }
        }
        $emitted = @()
        try { $emitted = @(Get-GsaGraphCollection -Uri '/beta/example') } catch { $caught = $_ }

        $caught.Exception.Message | Should -Be 'Graph collection pagination validation failed.' -Because $Label
        $emitted | Should -HaveCount 0
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 1 -Exactly
    }

    It 'rejects a top-level response array without another dispatch or partial output' {
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest {
            [pscustomobject]@{ value = @([pscustomobject]@{ id = 'first-envelope' }) }
            [pscustomobject]@{ value = @([pscustomobject]@{ id = 'second-envelope' }) }
        }
        $emitted = @()
        try { $emitted = @(Get-GsaGraphCollection -Uri '/beta/example') } catch { $caught = $_ }

        $caught.Exception.Message | Should -Be 'Graph collection pagination validation failed.'
        $emitted | Should -HaveCount 0
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 1 -Exactly
    }

    It 'applies the declared parameter ranges before dispatch' {
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest { throw 'must not dispatch' }

        { Get-GsaGraphCollection -Uri '/beta/example' -MaximumPages 1001 } | Should -Throw
        { Get-GsaGraphCollection -Uri '/beta/example' -MaximumItems 100001 } | Should -Throw
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }
}
