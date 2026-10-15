#Requires -Version 7.6
param(
    [Parameter(Mandatory)][int] $Port,
    [Parameter(Mandatory)][ValidateSet('valid','redirect','wrongType','parameterizedType','badStatus','empty','truncated','oversizedLength','oversizedBody','slowBody','proxySentinel')][string] $Scenario,
    [Parameter(Mandatory)][string] $ReadyPath,
    [Parameter(Mandatory)][string] $RequestPath,
    [string] $BodyPath
)

$ErrorActionPreference = 'Stop'
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
$requests = [Collections.Generic.List[string]]::new()
try {
    $listener.Start()
    Set-Content -LiteralPath $ReadyPath -Value 'ready' -Encoding ascii
    $maximumRequests = if ($Scenario -eq 'redirect') { 2 } else { 1 }
    for ($requestNumber = 1; $requestNumber -le $maximumRequests; $requestNumber++) {
        if ($Scenario -eq 'proxySentinel') {
            $wait = [Diagnostics.Stopwatch]::StartNew()
            while (-not $listener.Pending() -and $wait.Elapsed -lt [TimeSpan]::FromSeconds(1.5)) {
                Start-Sleep -Milliseconds 20
            }
            if (-not $listener.Pending()) { break }
        }
        if ($requestNumber -gt 1) {
            $wait = [Diagnostics.Stopwatch]::StartNew()
            while (-not $listener.Pending() -and $wait.Elapsed -lt [TimeSpan]::FromMilliseconds(700)) {
                Start-Sleep -Milliseconds 20
            }
            if (-not $listener.Pending()) { break }
        }
        $client = $listener.AcceptTcpClient()
        try {
            $client.NoDelay = $true
            $stream = $client.GetStream()
            $headerBytes = [Collections.Generic.List[byte]]::new()
            while ($headerBytes.Count -lt 16384) {
                $next = $stream.ReadByte()
                if ($next -lt 0) { break }
                $headerBytes.Add([byte]$next)
                $count = $headerBytes.Count
                if ($count -ge 4 -and $headerBytes[$count-4] -eq 13 -and $headerBytes[$count-3] -eq 10 -and
                    $headerBytes[$count-2] -eq 13 -and $headerBytes[$count-1] -eq 10) { break }
            }
            $requests.Add([Text.Encoding]::ASCII.GetString($headerBytes.ToArray()))

            $body = if ($BodyPath) { [IO.File]::ReadAllBytes($BodyPath) } else { [byte[]](1, 2, 3, 4) }
            $status = '200 OK'
            $contentType = 'application/pkix-crl'
            $contentLength = [string]$body.Length
            switch ($Scenario) {
                'redirect' { $status = '302 Found'; $contentType = 'text/plain'; $contentLength = '0' }
                'wrongType' { $contentType = 'text/plain' }
                'parameterizedType' { $contentType = 'application/pkix-crl; charset=binary' }
                'badStatus' { $status = '503 Service Unavailable' }
                'empty' { $body = [byte[]]::new(0); $contentLength = '0' }
                'truncated' { $contentLength = [string]($body.Length + 4) }
                'oversizedLength' { $body = [byte[]]::new(0); $contentLength = '1048577' }
                'oversizedBody' { $body = [byte[]]::new(1048577); $contentLength = $null }
                'slowBody' { $contentLength = [string]$body.Length }
                'proxySentinel' { $status = '407 Proxy Authentication Required'; $contentType = 'text/plain'; $contentLength = '0' }
            }
            $headers = "HTTP/1.1 $status`r`nContent-Type: $contentType`r`nConnection: close`r`n"
            if ($null -ne $contentLength) { $headers += "Content-Length: $contentLength`r`n" }
            if ($Scenario -eq 'redirect') { $headers += "Location: http://127.0.0.1:$Port/final`r`n" }
            $headers += "`r`n"
            $headerOutput = [Text.Encoding]::ASCII.GetBytes($headers)
            $stream.Write($headerOutput, 0, $headerOutput.Length)
            $stream.Flush()
            if ($Scenario -eq 'slowBody') {
                $stream.WriteByte(1)
                $stream.Flush()
                Start-Sleep -Seconds 2
            }
            elseif ($body.Length -gt 0) {
                try { $stream.Write($body, 0, $body.Length); $stream.Flush() } catch [IO.IOException] { }
            }
        }
        finally {
            if ($stream) { $stream.Dispose() }
            $client.Dispose()
        }
    }
}
finally {
    $listener.Stop()
    Set-Content -LiteralPath $RequestPath -Value ($requests -join "`n---REQUEST---`n") -Encoding ascii
}
