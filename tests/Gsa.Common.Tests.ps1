BeforeAll {
    function Invoke-MgGraphRequest {}
    Import-Module (Join-Path $PSScriptRoot '..\scripts\modules\Gsa.Common.psm1') -Force
}

AfterAll {
    Remove-Item Function:\Invoke-MgGraphRequest -ErrorAction SilentlyContinue
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
