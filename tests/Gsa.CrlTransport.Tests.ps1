#Requires -Version 7.6
BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $root 'scripts/modules/Gsa.Readiness.psm1') -Force
    $serverScript = Join-Path $PSScriptRoot 'helpers/Start-GsaCrlLoopbackServer.ps1'
    $fixtureScript = Join-Path $PSScriptRoot 'helpers/Invoke-GsaCrlReadinessFixture.ps1'
    . (Join-Path $PSScriptRoot 'helpers/New-GsaTestCrl.ps1')

    function Start-CrlLoopbackServer([string] $Scenario, [byte[]] $Body) {
        $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $probe.Start()
        $port = ([Net.IPEndPoint]$probe.LocalEndpoint).Port
        $probe.Stop()
        $readyPath = Join-Path $TestDrive "$Scenario-$port.ready"
        $requestPath = Join-Path $TestDrive "$Scenario-$port.request"
        $bodyPath = Join-Path $TestDrive "$Scenario-$port.crl"
        if ($null -eq $Body) {
            $Body = New-GsaTestCrl -ThisUpdate ([DateTimeOffset]'2026-10-01T00:00:00Z') -NextUpdate ([DateTimeOffset]'2026-11-01T00:00:00Z')
        }
        [IO.File]::WriteAllBytes($bodyPath, $Body)
        $startParameters = @{
            FilePath = (Get-Process -Id $PID).Path
            ArgumentList = @(
                '-NoLogo', '-NoProfile', '-File', $serverScript, '-Port', $port,
                '-Scenario', $Scenario, '-ReadyPath', $readyPath, '-RequestPath', $requestPath, '-BodyPath', $bodyPath
            )
            PassThru = $true
        }
        if ($IsWindows) { $startParameters.WindowStyle = 'Hidden' }
        $process = Start-Process @startParameters
        try {
            $deadline = [DateTimeOffset]::UtcNow.AddSeconds(5)
            while (-not (Test-Path -LiteralPath $readyPath) -and [DateTimeOffset]::UtcNow -lt $deadline) {
                if ($process.HasExited) { throw "Loopback server exited before readiness for $Scenario." }
                Start-Sleep -Milliseconds 20
            }
            if (-not (Test-Path -LiteralPath $readyPath)) { throw "Loopback server did not start for $Scenario." }
            [pscustomobject]@{ Process=$process; Port=$port; RequestPath=$requestPath; BodyPath=$bodyPath; Body=$Body }
        }
        catch {
            Stop-CrlLoopbackProcess $process
            throw
        }
    }

    function Stop-CrlLoopbackProcess([Diagnostics.Process] $Process) {
        try {
            if (-not $Process.HasExited) {
                try { $Process.Kill($true) }
                catch [InvalidOperationException] { }
                catch [ComponentModel.Win32Exception] { if (-not $Process.HasExited) { throw } }
            }
            try {
                if (-not $Process.WaitForExit(5000)) { throw 'Loopback helper process did not exit during cleanup.' }
            }
            catch [InvalidOperationException] { }
        }
        finally { $Process.Dispose() }
    }

    function Stop-CrlLoopbackServer([object] $Server) {
        Stop-CrlLoopbackProcess $Server.Process
    }
}

Describe 'Bounded CRL HTTP transport' {
    It 'streams and hashes one exact anonymous CRL response' {
        $server = Start-CrlLoopbackServer 'valid'
        try {
            $result = Get-GsaBoundedCrlEvidence -Uri "http://127.0.0.1:$($server.Port)/crl"
            $server.Process.WaitForExit(5000) | Should -BeTrue
            $result.published | Should -BeTrue
            $result.actualSha256 | Should -BeExactly ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($server.Body)))
            $result.derDecoded | Should -BeTrue
            $result.observedThisUpdate | Should -BeExactly '2026-10-01T00:00:00.0000000+00:00'
            $result.observedNextUpdate | Should -BeExactly '2026-11-01T00:00:00.0000000+00:00'
            @($result.PSObject.Properties.Name) | Should -Be @('published','actualSha256','derDecoded','observedThisUpdate','observedNextUpdate')
            $request = Get-Content -LiteralPath $server.RequestPath -Raw
            $request | Should -Match '^GET /crl HTTP/'
            $request | Should -Match 'Accept: application/pkix-crl'
            $request | Should -Not -Match '(?im)^(Authorization|Cookie):'
        }
        finally { Stop-CrlLoopbackServer $server }
    }

    It 'fails closed for <scenario> without hashing partial bytes' -ForEach @(
        @{ scenario='wrongType' }, @{ scenario='parameterizedType' }, @{ scenario='badStatus' }, @{ scenario='empty' },
        @{ scenario='truncated' }, @{ scenario='oversizedLength' }, @{ scenario='oversizedBody' }
    ) {
        $server = Start-CrlLoopbackServer $scenario
        try {
            $result = Get-GsaBoundedCrlEvidence -Uri "http://127.0.0.1:$($server.Port)/crl"
            $result.published | Should -BeFalse
            $result.actualSha256 | Should -BeNullOrEmpty
            $result.derDecoded | Should -BeFalse
            $result.observedThisUpdate | Should -BeNullOrEmpty
            $result.observedNextUpdate | Should -BeNullOrEmpty
            ($result | ConvertTo-Json -Compress) | Should -Not -Match 'http|error|exception'
        }
        finally { Stop-CrlLoopbackServer $server }
    }

    It 'does not follow redirects' {
        $server = Start-CrlLoopbackServer 'redirect'
        try {
            (Get-GsaBoundedCrlEvidence -Uri "http://127.0.0.1:$($server.Port)/redirect").published | Should -BeFalse
            $server.Process.WaitForExit(5000) | Should -BeTrue
            ([regex]::Matches((Get-Content -LiteralPath $server.RequestPath -Raw), '(?m)^GET ')).Count | Should -Be 1
        }
        finally { Stop-CrlLoopbackServer $server }
    }

    It 'bypasses a credentialed ambient proxy and reaches the origin directly' {
        $origin = $null
        $proxy = $null
        try {
            $origin = Start-CrlLoopbackServer 'valid'
            $proxy = Start-CrlLoopbackServer 'proxySentinel'
            $originUri = [Uri]"http://127.0.0.1:$($origin.Port)/crl"
            $proxyFixture = Join-Path $PSScriptRoot 'helpers/Invoke-GsaCrlProxyFixture.ps1'
            $output = & (Get-Process -Id $PID).Path -NoProfile -File $proxyFixture -Root $root -OriginUri $originUri.AbsoluteUri -ProxyUri "http://127.0.0.1:$($proxy.Port)" 2>&1
            $LASTEXITCODE | Should -Be 0
            $result = ($output | Out-String) | ConvertFrom-Json
            $result.published | Should -BeTrue
            $origin.Process.WaitForExit(5000) | Should -BeTrue
            $proxy.Process.WaitForExit(5000) | Should -BeTrue
            $proxyRequest = Get-Content -LiteralPath $proxy.RequestPath -Raw
            $proxyRequest | Should -Not -Match '(?m)^(GET|CONNECT) '
            $proxyRequest | Should -Not -Match 'Proxy-Authorization|proxy-user|proxy-secret'
        }
        finally {
            if ($origin) { Stop-CrlLoopbackServer $origin }
            if ($proxy) { Stop-CrlLoopbackServer $proxy }
        }
    }

    It 'applies one deadline through a slow response body' {
        $server = Start-CrlLoopbackServer 'slowBody'
        try {
            $watch = [Diagnostics.Stopwatch]::StartNew()
            $result = Get-GsaBoundedCrlEvidence -Uri "http://127.0.0.1:$($server.Port)/crl" -TotalTimeout ([TimeSpan]::FromMilliseconds(250))
            $watch.Stop()
            $result.published | Should -BeFalse
            $result.actualSha256 | Should -BeNullOrEmpty
            $result.derDecoded | Should -BeFalse
            $watch.Elapsed | Should -BeLessThan ([TimeSpan]::FromSeconds(1.5))
        }
        finally { Stop-CrlLoopbackServer $server }
    }

    It 'rejects malformed or credential-bearing locations before dispatch <uri>' -ForEach @(
        @{ uri='not a uri' }, @{ uri='ftp://example.test/crl' },
        @{ uri='http://user:secret@example.test/crl' }, @{ uri='https://example.test/crl#fragment' }
    ) {
        $result = Get-GsaBoundedCrlEvidence -Uri $uri
        $result.published | Should -BeFalse
        $result.actualSha256 | Should -BeNullOrEmpty
        $result.derDecoded | Should -BeFalse
        ($result | ConvertTo-Json -Compress) | Should -Not -Match 'example|secret|fragment'
    }

    It 'wires the actual bounded transport into the read-only entrypoint' {
        $server = Start-CrlLoopbackServer 'valid'
        try {
            $uri = "http://127.0.0.1:$($server.Port)/crl"
            $nativeOutput = & (Get-Process -Id $PID).Path -NoProfile -File $fixtureScript -Case actualTransport -Root $root -CrlUri $uri -CrlPath $server.BodyPath 2>&1
            $LASTEXITCODE | Should -Be 1
            $summary = ($nativeOutput | Out-String) | ConvertFrom-Json -Depth 40
            $crl = @($summary.checks | Where-Object name -eq 'CRL publication')
            $crl.Count | Should -Be 1
            $crl[0].actual.publicationVerified | Should -BeTrue
            $crl[0].actual.expiryObserved | Should -BeTrue
            ([DateTimeOffset]$crl[0].actual.observedThisUpdate).ToUniversalTime().ToString('O') | Should -BeExactly '2026-10-01T00:00:00.0000000+00:00'
            ([DateTimeOffset]$crl[0].actual.observedNextUpdate).ToUniversalTime().ToString('O') | Should -BeExactly '2026-11-01T00:00:00.0000000+00:00'
            $crl[0].actual.signatureVerified | Should -BeFalse
            $crl[0].actual.issuerVerified | Should -BeFalse
            ($summary | ConvertTo-Json -Depth 40) | Should -Not -Match [regex]::Escape($uri)
            $server.Process.WaitForExit(5000) | Should -BeTrue
        }
        finally { Stop-CrlLoopbackServer $server }
    }

    It 'decodes signed CRL dates and rejects unsafe temporal states <name>' -ForEach @(
        @{ name='GeneralizedTime'; start=[DateTimeOffset]'2051-01-01T00:00:00Z'; next=[DateTimeOffset]'2051-02-01T00:00:00Z'; generalized=$true; now=[DateTimeOffset]'2051-01-15T00:00:00Z'; code='ObservedDatesUntrusted'; status='Warning'; observed=$true },
        @{ name='inverted dates'; start=[DateTimeOffset]'2026-10-20T00:00:00Z'; next=[DateTimeOffset]'2026-10-19T00:00:00Z'; generalized=$false; now=[DateTimeOffset]'2026-10-15T00:00:00Z'; code='ObservedValidityInverted'; status='Fail'; observed=$true },
        @{ name='future thisUpdate'; start=[DateTimeOffset]'2026-10-20T00:00:00Z'; next=[DateTimeOffset]'2026-11-20T00:00:00Z'; generalized=$false; now=[DateTimeOffset]'2026-10-15T00:00:00Z'; code='ObservedThisUpdateFuture'; status='Fail'; observed=$true },
        @{ name='expired nextUpdate'; start=[DateTimeOffset]'2026-09-01T00:00:00Z'; next=[DateTimeOffset]'2026-10-14T00:00:00Z'; generalized=$false; now=[DateTimeOffset]'2026-10-15T00:00:00Z'; code='ObservedExpiryExpired'; status='Fail'; observed=$true }
    ) {
        $body = New-GsaTestCrl -ThisUpdate $start -NextUpdate $next -UseGeneralizedTime:$generalized
        $server = Start-CrlLoopbackServer valid $body
        try {
            $evidence = Get-GsaBoundedCrlEvidence -Uri "http://127.0.0.1:$($server.Port)/crl"
            $evidence.derDecoded | Should -BeTrue
            $state = [pscustomobject]@{
                published=$evidence.published; expectedSha256=$evidence.actualSha256; actualSha256=$evidence.actualSha256
                nextUpdate='2099-01-01T00:00:00Z'; derDecoded=$evidence.derDecoded
                observedThisUpdate=$evidence.observedThisUpdate; observedNextUpdate=$evidence.observedNextUpdate
            }
            $check = Test-GsaCrlReadiness -CrlState $state -Now $now
            $check.Status | Should -BeExactly $status
            $check.Actual.failureCode | Should -BeExactly $code
            $check.Actual.expiryObserved | Should -Be $observed
        }
        finally { Stop-CrlLoopbackServer $server }
    }

    It 'fails closed for malformed or trailing DER <name>' -ForEach @(
        @{ name='missing nextUpdate'; transform={ param($bytes) New-GsaTestCrl -ThisUpdate ([DateTimeOffset]'2026-10-01T00:00:00Z') -NextUpdate $null } },
        @{ name='malformed'; transform={ param($bytes) [byte[]]$bytes[0..($bytes.Length - 2)] } },
        @{ name='trailing data'; transform={ param($bytes) [byte[]]($bytes + 0) } }
    ) {
        $valid = New-GsaTestCrl -ThisUpdate ([DateTimeOffset]'2026-10-01T00:00:00Z') -NextUpdate ([DateTimeOffset]'2026-11-01T00:00:00Z')
        $server = Start-CrlLoopbackServer valid (& $transform $valid)
        try {
            $result = Get-GsaBoundedCrlEvidence -Uri "http://127.0.0.1:$($server.Port)/crl"
            $result.published | Should -BeFalse
            $result.actualSha256 | Should -BeNullOrEmpty
            $result.derDecoded | Should -BeFalse
            ($result | ConvertTo-Json -Compress) | Should -Not -Match 'http|error|exception|CANARY'
        }
        finally { Stop-CrlLoopbackServer $server }
    }
}
