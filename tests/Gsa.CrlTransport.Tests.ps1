#Requires -Version 7.6
BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $root 'scripts/modules/Gsa.Readiness.psm1') -Force
    $serverScript = Join-Path $PSScriptRoot 'helpers/Start-GsaCrlLoopbackServer.ps1'
    $fixtureScript = Join-Path $PSScriptRoot 'helpers/Invoke-GsaCrlReadinessFixture.ps1'

    function Start-CrlLoopbackServer([string] $Scenario) {
        $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $probe.Start()
        $port = ([Net.IPEndPoint]$probe.LocalEndpoint).Port
        $probe.Stop()
        $readyPath = Join-Path $TestDrive "$Scenario-$port.ready"
        $requestPath = Join-Path $TestDrive "$Scenario-$port.request"
        $startParameters = @{
            FilePath = (Get-Process -Id $PID).Path
            ArgumentList = @(
                '-NoLogo', '-NoProfile', '-File', $serverScript, '-Port', $port,
                '-Scenario', $Scenario, '-ReadyPath', $readyPath, '-RequestPath', $requestPath
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
            [pscustomobject]@{ Process=$process; Port=$port; RequestPath=$requestPath }
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
            $result.actualSha256 | Should -BeExactly ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]](1,2,3,4))))
            @($result.PSObject.Properties.Name) | Should -Be @('published','actualSha256')
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
        $previousProxy = [Net.Http.HttpClient]::DefaultProxy
        try {
            $origin = Start-CrlLoopbackServer 'valid'
            $proxy = Start-CrlLoopbackServer 'proxySentinel'
            $credentialedProxy = [Net.WebProxy]::new([Uri]"http://127.0.0.1:$($proxy.Port)", $false)
            $credentialedProxy.Credentials = [Net.NetworkCredential]::new('proxy-user', 'proxy-secret')
            [Net.Http.HttpClient]::DefaultProxy = $credentialedProxy

            $originUri = [Uri]"http://127.0.0.1:$($origin.Port)/crl"
            $credentialedProxy.IsBypassed($originUri) | Should -BeFalse
            $credentialedProxy.GetProxy($originUri).Port | Should -Be $proxy.Port
            $result = Get-GsaBoundedCrlEvidence -Uri $originUri.AbsoluteUri
            $result.published | Should -BeTrue
            $origin.Process.WaitForExit(5000) | Should -BeTrue
            $proxy.Process.WaitForExit(5000) | Should -BeTrue
            $proxyRequest = Get-Content -LiteralPath $proxy.RequestPath -Raw
            $proxyRequest | Should -Not -Match '(?m)^(GET|CONNECT) '
            $proxyRequest | Should -Not -Match 'Proxy-Authorization|proxy-user|proxy-secret'
        }
        finally {
            [Net.Http.HttpClient]::DefaultProxy = $previousProxy
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
        ($result | ConvertTo-Json -Compress) | Should -Not -Match 'example|secret|fragment'
    }

    It 'wires the actual bounded transport into the read-only entrypoint' {
        $server = Start-CrlLoopbackServer 'valid'
        try {
            $uri = "http://127.0.0.1:$($server.Port)/crl"
            $nativeOutput = & (Get-Process -Id $PID).Path -NoProfile -File $fixtureScript -Case actualTransport -Root $root -CrlUri $uri 2>&1
            $LASTEXITCODE | Should -Be 1
            $summary = ($nativeOutput | Out-String) | ConvertFrom-Json -Depth 40
            $crl = @($summary.checks | Where-Object name -eq 'CRL publication')
            $crl.Count | Should -Be 1
            $crl[0].actual.publicationVerified | Should -BeTrue
            ($summary | ConvertTo-Json -Depth 40) | Should -Not -Match [regex]::Escape($uri)
            $server.Process.WaitForExit(5000) | Should -BeTrue
        }
        finally { Stop-CrlLoopbackServer $server }
    }
}
