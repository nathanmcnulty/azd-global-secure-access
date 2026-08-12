Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Gsa.Common.psm1') -Force

function ConvertTo-GsaBase64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-GsaBase64Url {
    param([Parameter(Mandatory)][string]$Value)
    $base64 = $Value.Replace('-', '+').Replace('_', '/')
    switch ($base64.Length % 4) {
        2 { $base64 += '==' }
        3 { $base64 += '=' }
    }
    $result = [Convert]::FromBase64String($base64)
    return ,$result
}

function Get-GsaDerLength {
    param([Parameter(Mandatory)][int]$Length)
    if ($Length -lt 128) {
        return [byte[]]@($Length)
    }
    if ($Length -lt 256) {
        return [byte[]]@(0x81, $Length)
    }
    if ($Length -lt 65536) {
        return [byte[]]@(0x82, [byte](($Length -shr 8) -band 0xff), [byte]($Length -band 0xff))
    }
    return [byte[]]@(0x83, [byte](($Length -shr 16) -band 0xff), [byte](($Length -shr 8) -band 0xff), [byte]($Length -band 0xff))
}

function Get-GsaDerChild {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [int]$Offset = 0
    )

    if ($Bytes[$Offset] -ne 0x30) {
        throw "Expected DER SEQUENCE at offset $Offset."
    }
    $start = $Offset
    $Offset++
    $firstLength = $Bytes[$Offset]
    $Offset++
    if (($firstLength -band 0x80) -eq 0) {
        $contentLength = $firstLength
    } else {
        $lengthBytes = $firstLength -band 0x7f
        $contentLength = 0
        for ($index = 0; $index -lt $lengthBytes; $index++) {
            $contentLength = ($contentLength -shl 8) + $Bytes[$Offset + $index]
        }
        $Offset += $lengthBytes
    }
    $totalLength = ($Offset - $start) + $contentLength
    return [pscustomobject]@{
        Start         = $start
        ContentStart  = $Offset
        ContentLength = $contentLength
        TotalLength   = $totalLength
        Bytes         = [byte[]]$Bytes[$start..($start + $totalLength - 1)]
    }
}

function Invoke-GsaKeyVault {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [AllowNull()][object]$Body
    )

    $delay = 2
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        $parameters = @{
            Method  = $Method
            Uri     = $Uri
            Headers = @{ Authorization = "Bearer $(Get-GsaPlainTextToken -ResourceUrl 'https://vault.azure.net')" }
        }
        if ($null -ne $Body) {
            $parameters.Body = $Body | ConvertTo-Json -Depth 15
            $parameters.ContentType = 'application/json'
        }
        try {
            return Invoke-RestMethod @parameters
        } catch {
            $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            $transient = $statusCode -in 401, 403, 408, 429 -or $statusCode -ge 500
            if (-not $transient -or $attempt -eq 10) {
                throw
            }
            Start-Sleep -Seconds $delay
            $delay = [Math]::Min($delay * 2, 20)
        }
    }
}

function Get-GsaKeyVaultCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$CertificateName
    )

    $response = Invoke-GsaKeyVault -Method GET -Uri "https://$VaultName.vault.azure.net/certificates/$CertificateName`?api-version=7.5"
    $bytes = [Convert]::FromBase64String($response.cer)
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
    $pem = "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($bytes, 'InsertLineBreaks') -replace "`r`n", "`n")`n-----END CERTIFICATE-----"
    return [pscustomobject]@{
        Certificate = $certificate
        Pem         = $pem
        KeyId       = $response.kid
        Thumbprint  = $certificate.Thumbprint
        NotAfter    = $certificate.NotAfter
    }
}

function Assert-GsaRootCertificate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$CertificateInfo)

    $certificate = $CertificateInfo.Certificate
    $basic = $certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | Select-Object -First 1
    if (-not $basic) {
        throw 'Root certificate has no Basic Constraints extension.'
    }
    $basic = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$basic
    if (-not $basic.CertificateAuthority) {
        throw 'Existing Key Vault certificate is not a CA.'
    }
    if ($basic.HasPathLengthConstraint -and $basic.PathLengthConstraint -lt 2) {
        throw "Existing root pathLen=$($basic.PathLengthConstraint) cannot support the GSA CA hierarchy."
    }

    $usage = $certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' } | Select-Object -First 1
    $required = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
    if (-not $usage -or (([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]$usage).KeyUsages -band $required) -ne $required) {
        throw 'Root certificate must allow keyCertSign and cRLSign.'
    }

    $key = Invoke-GsaKeyVault -Method GET -Uri "$($CertificateInfo.KeyId)?api-version=7.5"
    if ($key.key.kty -ne 'RSA-HSM') {
        throw "Existing root uses '$($key.key.kty)' instead of RSA-HSM."
    }
    if ($certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow.AddMonths(6)) {
        throw 'Existing root expires too soon to meet the GSA minimum.'
    }
}

function Get-OrCreateGsaRootCertificate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$CertificateName,
        [Parameter(Mandatory)][string]$CommonName,
        [Parameter(Mandatory)][string]$OrganizationName
    )

    $certificate = $null
    try {
        $certificate = Get-GsaKeyVaultCertificate -VaultName $VaultName -CertificateName $CertificateName
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($statusCode -ne 404) {
            throw
        }
    }

    if (-not $certificate) {
        if (-not $PSCmdlet.ShouldProcess("$VaultName/$CertificateName", 'Create non-exportable RSA-HSM 4096 root CA')) {
            return
        }
        $policy = @{
            policy = @{
                key_props = @{
                    exportable = $false
                    kty        = 'RSA-HSM'
                    key_size   = 4096
                    reuse_key  = $false
                }
                secret_props = @{ contentType = 'application/x-pem-file' }
                x509_props = @{
                    subject           = "CN=$CommonName, O=$OrganizationName"
                    key_usage         = @('digitalSignature', 'keyCertSign', 'cRLSign')
                    validity_months   = 120
                    basic_constraints = @{ ca = $true }
                }
                issuer = @{ name = 'Self' }
                attributes = @{ enabled = $true }
            }
        }
        Invoke-GsaKeyVault -Method POST -Uri "https://$VaultName.vault.azure.net/certificates/$CertificateName/create?api-version=7.5" -Body $policy | Out-Null
        for ($attempt = 1; $attempt -le 30; $attempt++) {
            Start-Sleep -Seconds 4
            try {
                $certificate = Get-GsaKeyVaultCertificate -VaultName $VaultName -CertificateName $CertificateName
                break
            } catch {
                if ($attempt -eq 30) {
                    throw
                }
            }
        }
    }
    Assert-GsaRootCertificate -CertificateInfo $certificate
    return $certificate
}

function Invoke-GsaKeyVaultSign {
    param(
        [Parameter(Mandatory)][string]$KeyId,
        [Parameter(Mandatory)][byte[]]$Hash
    )

    $result = Invoke-GsaKeyVault -Method POST -Uri "$KeyId/sign?api-version=7.5" -Body @{
        alg   = 'RS256'
        value = ConvertTo-GsaBase64Url -Bytes $Hash
    }
    $signature = [byte[]](ConvertFrom-GsaBase64Url -Value $result.value)
    return ,$signature
}

function Join-GsaSignedDer {
    param(
        [Parameter(Mandatory)][byte[]]$TbsBytes,
        [Parameter(Mandatory)][byte[]]$Signature
    )

    [byte[]]$algorithm = @(0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00)
    [byte[]]$signatureContent = @(0x00) + $Signature
    [byte[]]$signatureValue = @(0x03) + (Get-GsaDerLength -Length $signatureContent.Length) + $signatureContent
    [byte[]]$content = $TbsBytes + $algorithm + $signatureValue
    $result = [byte[]](@(0x30) + (Get-GsaDerLength -Length $content.Length) + $content)
    return ,$result
}

function ConvertTo-GsaSignedCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CsrPem,
        [Parameter(Mandatory)][pscustomobject]$Issuer,
        [Parameter(Mandatory)][string]$CrlUrl,
        [int]$ValidityYears = 5
    )

    $csr = [System.Security.Cryptography.X509Certificates.CertificateRequest]::LoadSigningRequestPem(
        $CsrPem,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.X509Certificates.CertificateRequestLoadOptions]::Default,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $csr.SubjectName,
        $csr.PublicKey,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $true, 1, $true)
    )
    $usage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($usage, $true)
    )
    $ekuOids = [System.Security.Cryptography.OidCollection]::new()
    [void]$ekuOids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids, $false)
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false)
    )
    $issuerSki = $Issuer.Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.14' } | Select-Object -First 1
    if (-not $issuerSki) {
        throw 'Issuer certificate has no Subject Key Identifier.'
    }
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509AuthorityKeyIdentifierExtension]::CreateFromSubjectKeyIdentifier(
            [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]$issuerSki
        )
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.CertificateRevocationListBuilder]::BuildCrlDistributionPointExtension(
            [string[]]@($CrlUrl),
            $false
        )
    )

    $serial = [byte[]]::new(16)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($serial)
    $serial[0] = $serial[0] -band 0x7f
    $notBefore = [DateTimeOffset]::UtcNow.AddMinutes(-5)
    $requestedNotAfter = [DateTimeOffset]::UtcNow.AddYears($ValidityYears)
    $issuerLimit = [DateTimeOffset]::new($Issuer.Certificate.NotAfter.ToUniversalTime()).AddMinutes(-5)
    $notAfter = if ($requestedNotAfter -lt $issuerLimit) { $requestedNotAfter } else { $issuerLimit }
    if ($notAfter -le [DateTimeOffset]::UtcNow.AddMonths(6)) {
        throw 'The root CA cannot meet the six-month GSA certificate minimum.'
    }

    $dummyKey = [System.Security.Cryptography.RSA]::Create(4096)
    try {
        $generator = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA(
            $dummyKey,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $dummy = $request.Create($Issuer.Certificate.SubjectName, $generator, $notBefore, $notAfter, $serial)
    } finally {
        $dummyKey.Dispose()
    }

    $outer = Get-GsaDerChild -Bytes $dummy.RawData
    $tbs = Get-GsaDerChild -Bytes $dummy.RawData -Offset $outer.ContentStart
    $hash = [System.Security.Cryptography.SHA256]::HashData($tbs.Bytes)
    $signature = Invoke-GsaKeyVaultSign -KeyId $Issuer.KeyId -Hash $hash
    $issuerKey = $Issuer.Certificate.PublicKey.GetRSAPublicKey()
    if (-not $issuerKey.VerifyData($tbs.Bytes, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)) {
        throw 'GSA certificate signature verification failed.'
    }
    [byte[]]$der = Join-GsaSignedDer -TbsBytes $tbs.Bytes -Signature $signature
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
    $pem = "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($der, 'InsertLineBreaks') -replace "`r`n", "`n")`n-----END CERTIFICATE-----"
    return [pscustomobject]@{
        Certificate = $certificate
        Pem         = $pem
        Thumbprint  = $certificate.Thumbprint
    }
}

function ConvertTo-GsaCrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Issuer,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$Number,
        [int]$NextUpdateDays = 30
    )

    $issuerSki = $Issuer.Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.14' } | Select-Object -First 1
    if (-not $issuerSki) {
        throw 'Issuer certificate has no Subject Key Identifier.'
    }
    $aki = [System.Security.Cryptography.X509Certificates.X509AuthorityKeyIdentifierExtension]::CreateFromSubjectKeyIdentifier(
        [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]$issuerSki
    )
    $builder = [System.Security.Cryptography.X509Certificates.CertificateRevocationListBuilder]::new()
    $dummyKey = [System.Security.Cryptography.RSA]::Create(4096)
    try {
        $generator = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA(
            $dummyKey,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $dummy = $builder.Build(
            $Issuer.Certificate.SubjectName,
            $generator,
            $Number,
            [DateTimeOffset]::UtcNow.AddDays($NextUpdateDays),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            $aki,
            [DateTimeOffset]::UtcNow
        )
    } finally {
        $dummyKey.Dispose()
    }

    $outer = Get-GsaDerChild -Bytes $dummy
    $tbs = Get-GsaDerChild -Bytes $dummy -Offset $outer.ContentStart
    $hash = [System.Security.Cryptography.SHA256]::HashData($tbs.Bytes)
    $signature = Invoke-GsaKeyVaultSign -KeyId $Issuer.KeyId -Hash $hash
    $issuerKey = $Issuer.Certificate.PublicKey.GetRSAPublicKey()
    if (-not $issuerKey.VerifyData($tbs.Bytes, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)) {
        throw 'CRL signature verification failed.'
    }
    [byte[]]$result = Join-GsaSignedDer -TbsBytes $tbs.Bytes -Signature $signature
    return ,$result
}

function Invoke-GsaStorageRequest {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'PUT')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [AllowNull()][object]$Body,
        [string]$ContentType = 'application/octet-stream',
        [hashtable]$AdditionalHeaders
    )

    $delay = 2
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        $headers = @{
            Authorization  = "Bearer $(Get-GsaPlainTextToken -ResourceUrl 'https://storage.azure.com/')"
            'x-ms-date'    = [DateTime]::UtcNow.ToString('R')
            'x-ms-version' = '2023-11-03'
        }
        if ($AdditionalHeaders) {
            foreach ($entry in $AdditionalHeaders.GetEnumerator()) {
                $headers[$entry.Key] = $entry.Value
            }
        }
        $parameters = @{
            Method      = $Method
            Uri         = $Uri
            Headers     = $headers
            ContentType = $ContentType
        }
        if ($null -ne $Body) {
            $parameters.Body = $Body
        }
        try {
            return Invoke-RestMethod @parameters
        } catch {
            $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            $transient = $statusCode -in 401, 403, 408, 429 -or ($Method -eq 'PUT' -and $statusCode -eq 404) -or $statusCode -ge 500
            if (-not $transient -or $attempt -eq 10) {
                throw
            }
            Start-Sleep -Seconds $delay
            $delay = [Math]::Min($delay * 2, 20)
        }
    }
}

function Invoke-GsaStorageBlobUpload {
    param(
        [Parameter(Mandatory)][string]$StorageAccountName,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][byte[]]$Content,
        [Parameter(Mandatory)][string]$ContentType
    )

    $encoded = ($Name.Split('/') | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'
    $uri = "https://$StorageAccountName.blob.core.windows.net/`$web/$encoded"
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        try {
            Invoke-GsaStorageRequest -Method PUT -Uri $uri -Body $Content -ContentType $ContentType -AdditionalHeaders @{
                'x-ms-blob-type' = 'BlockBlob'
            } | Out-Null
            return
        } catch {
            $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            if ($statusCode -eq 403 -and $attempt -lt 12) {
                Start-Sleep -Seconds 10
                continue
            }
            throw
        }
    }
}

function Enter-GsaCrlPublicationLease {
    param(
        [Parameter(Mandatory)][string]$StorageAccountName,
        [string]$LockBlobName = 'gsa-crl-publication.lock'
    )

    $uri = "https://$StorageAccountName.blob.core.windows.net/`$web/$LockBlobName"
    try {
        Invoke-GsaStorageRequest -Method PUT -Uri $uri -Body ([byte[]]@()) -AdditionalHeaders @{
            'x-ms-blob-type' = 'BlockBlob'
            'If-None-Match'  = '*'
        } | Out-Null
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($statusCode -notin 409, 412) {
            throw
        }
    }

    $leaseId = [guid]::NewGuid().ToString()
    for ($attempt = 1; $attempt -le 24; $attempt++) {
        try {
            Invoke-GsaStorageRequest -Method PUT -Uri "$uri`?comp=lease" -Body ([byte[]]@()) -AdditionalHeaders @{
                'x-ms-lease-action'      = 'acquire'
                'x-ms-lease-duration'    = '60'
                'x-ms-proposed-lease-id' = $leaseId
            } | Out-Null
            return [pscustomobject]@{ Uri = $uri; Id = $leaseId }
        } catch {
            $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            if ($statusCode -notin 409, 412 -or $attempt -eq 24) {
                throw
            }
            Start-Sleep -Seconds 5
        }
    }
}

function Invoke-GsaCrlPublicationLeaseRenewal {
    param([Parameter(Mandatory)][pscustomobject]$Lease)

    Invoke-GsaStorageRequest -Method PUT -Uri "$($Lease.Uri)?comp=lease" -Body ([byte[]]@()) -AdditionalHeaders @{
        'x-ms-lease-action' = 'renew'
        'x-ms-lease-id'     = $Lease.Id
    } | Out-Null
}

function Exit-GsaCrlPublicationLease {
    param([Parameter(Mandatory)][pscustomobject]$Lease)

    try {
        Invoke-GsaStorageRequest -Method PUT -Uri "$($Lease.Uri)?comp=lease" -Body ([byte[]]@()) -AdditionalHeaders @{
            'x-ms-lease-action' = 'release'
            'x-ms-lease-id'     = $Lease.Id
        } | Out-Null
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($statusCode -notin 409, 412) {
            throw
        }
    }
}

function Publish-GsaCrl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$StorageAccountName,
        [Parameter(Mandatory)][string]$WebEndpoint,
        [Parameter(Mandatory)][pscustomobject]$Issuer,
        [string]$CustomHostname,
        [string]$CrlFileName = 'gsa-tls-root-ca.crl',
        [switch]$EnsureStaticWebsite
    )

    $serviceUri = "https://$StorageAccountName.blob.core.windows.net/?restype=service&comp=properties"
    $serviceBody = @'
<?xml version="1.0" encoding="utf-8"?>
<StorageServiceProperties>
  <StaticWebsite>
    <Enabled>true</Enabled>
    <IndexDocument>index.html</IndexDocument>
  </StaticWebsite>
</StorageServiceProperties>
'@
    if ($EnsureStaticWebsite) {
        $serviceProperties = Invoke-GsaStorageRequest -Method GET -Uri $serviceUri
        $serviceRoot = $serviceProperties.StorageServiceProperties
        $staticWebsiteEnabled = $serviceRoot.PSObject.Properties['StaticWebsite'] -and
            [string]$serviceRoot.StaticWebsite.Enabled -eq 'true'
        if (-not $staticWebsiteEnabled -and $PSCmdlet.ShouldProcess($StorageAccountName, 'Enable static website using Microsoft Entra authorization')) {
            Invoke-GsaStorageRequest -Method PUT -Uri $serviceUri -Body $serviceBody -ContentType 'application/xml' | Out-Null
        }
    }

    $lease = Enter-GsaCrlPublicationLease -StorageAccountName $StorageAccountName
    try {
        $previous = [System.Numerics.BigInteger]::Zero
        $stateName = "$CrlFileName-state.json"
        try {
            $state = Invoke-GsaStorageRequest -Method GET -Uri "https://$StorageAccountName.blob.core.windows.net/`$web/$stateName"
            if ($state.crlNumber) {
                $previous = [System.Numerics.BigInteger]::Parse([string]$state.crlNumber)
            }
        } catch {
            $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            if ($statusCode -ne 404) {
                throw
            }
        }
        $clock = [System.Numerics.BigInteger]::new([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
        $number = if ($clock -gt $previous) { $clock } else { $previous + 1 }
        Invoke-GsaCrlPublicationLeaseRenewal -Lease $lease
        $crl = ConvertTo-GsaCrl -Issuer $Issuer -Number $number
        Invoke-GsaCrlPublicationLeaseRenewal -Lease $lease
        if ($PSCmdlet.ShouldProcess($StorageAccountName, "Publish CRL number $number")) {
            $stateBytes = [Text.Encoding]::UTF8.GetBytes((@{
                crlNumber  = $number.ToString()
                published  = [DateTimeOffset]::UtcNow.ToString('O')
                thumbprint = $Issuer.Thumbprint
            } | ConvertTo-Json -Compress))
            Invoke-GsaStorageBlobUpload -StorageAccountName $StorageAccountName -Name $stateName -Content $stateBytes -ContentType 'application/json'
            Invoke-GsaStorageBlobUpload -StorageAccountName $StorageAccountName -Name $CrlFileName -Content $crl -ContentType 'application/pkix-crl'
        }

        $websiteHost = ([uri]$WebEndpoint).Host
        $crlUrl = if ($CustomHostname) {
            "http://$CustomHostname/$CrlFileName"
        } else {
            "http://$websiteHost/$CrlFileName"
        }
        $expectedHash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($crl))
        $verified = $false
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            try {
                $response = Invoke-WebRequest -Uri $crlUrl -TimeoutSec 15
                $contentType = [string]$response.Headers['Content-Type']
                [byte[]]$downloadedCrl = $response.Content
                $downloadedHash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($downloadedCrl))
                if (
                    $response.StatusCode -eq 200 -and
                    $contentType.Split(';')[0] -eq 'application/pkix-crl' -and
                    $downloadedHash -eq $expectedHash
                ) {
                    $verified = $true
                    break
                }
            } catch {
                if ($attempt -eq 12) {
                    break
                }
            }
            Start-Sleep -Seconds 5
        }
        if (-not $verified) {
            throw "CRL publication could not be verified at '$crlUrl'. Refusing to create a certificate with this CDP."
        }
        return [pscustomobject]@{
            Url    = $crlUrl
            Number = $number.ToString()
            Bytes  = $crl.Length
            Sha256 = $expectedHash
        }
    } finally {
        Exit-GsaCrlPublicationLease -Lease $lease
    }
}

function Set-GsaTlsCertificate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][pscustomobject]$RootCertificate,
        [Parameter(Mandatory)][string]$CrlUrl,
        [Parameter(Mandatory)][string]$CommonName,
        [Parameter(Mandatory)][string]$OrganizationName,
        [switch]$Rotate,
        [switch]$AllowUndocumentedEnable
    )

    Assert-GsaPreviewGate -Feature 'Global Secure Access TLS certificate lifecycle' -Enabled $true
    $headers = @{ Prefer = 'include-unknown-enum-members' }
    $certificates = @(Get-GsaGraphCollection -Uri '/beta/networkAccess/tls/externalCertificateAuthorityCertificates' -Headers $headers)
    $active = @($certificates | Where-Object { $_.status -in 'active', 'enabled' })
    if ($active.Count -gt 1) {
        throw 'GSA reports multiple active certificates. Resolve this service state before continuing.'
    }
    if ($active.Count -eq 1 -and -not $Rotate) {
        return [pscustomobject]@{
            Id         = $active[0].id
            Name       = $active[0].name
            Status     = $active[0].status
            Changed    = $false
            ManualStep = $null
        }
    }

    $pending = @($certificates | Where-Object {
        $_.name -like 'GSAKV*' -and $_.status -in 'csrGenerated', 'enrolling', 'disabled', 'unknownFutureValue'
    })
    if ($pending.Count -gt 1) {
        throw 'Multiple pending GSAKV certificates exist. Resolve them in the Entra portal.'
    }

    $certificateObject = $null
    $csr = $null
    if ($pending.Count -eq 1) {
        $certificateObject = Invoke-MgGraphRequest -Method GET -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$($pending[0].id)?`$select=id,name,status,certificateSigningRequest,certificate,chain" -Headers $headers -OutputType PSObject
        if ($certificateObject.status -eq 'unknownFutureValue' -and -not $certificateObject.certificateSigningRequest -and -not $certificateObject.certificate) {
            throw "Pending certificate '$($certificateObject.name)' has an unknown transitional state and cannot be resumed safely."
        }
        $csr = $certificateObject.certificateSigningRequest
    }

    if (-not $certificateObject) {
        $name = 'GSAKV' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString('x').Substring(0, 7)
        if ($name.Length -gt 12) {
            $name = $name.Substring(0, 12)
        }
        $body = @{
            '@odata.type'  = '#microsoft.graph.networkaccess.externalCertificateAuthorityCertificate'
            name           = $name
            commonName     = $CommonName
            organizationName = $OrganizationName
        } | ConvertTo-Json
        if (-not $PSCmdlet.ShouldProcess($name, 'Create GSA TLS certificate signing request')) {
            return
        }
        $certificateObject = Invoke-MgGraphRequest -Method POST -Uri '/beta/networkAccess/tls/externalCertificateAuthorityCertificates' -Body $body -ContentType 'application/json' -OutputType PSObject
        $csr = $certificateObject.certificateSigningRequest
    }

    if ($csr) {
        $signed = ConvertTo-GsaSignedCertificate -CsrPem $csr -Issuer $RootCertificate -CrlUrl $CrlUrl
        $body = @{
            certificate = $signed.Pem
            chain       = $RootCertificate.Pem
        } | ConvertTo-Json -Depth 4
        if ($PSCmdlet.ShouldProcess($certificateObject.name, 'Upload signed GSA certificate and chain')) {
            Invoke-MgGraphRequest -Method PATCH -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$($certificateObject.id)" -Body $body -ContentType 'application/json' | Out-Null
        }
    }

    $state = Invoke-MgGraphRequest -Method GET -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$($certificateObject.id)" -Headers $headers -OutputType PSObject
    $manualStep = "Enable certificate '$($state.name)' in Entra admin center after the trusted root reaches pilot devices."
    if ($AllowUndocumentedEnable -and $state.status -notin 'active', 'enabled') {
        $body = @{ status = 'enabled' } | ConvertTo-Json -Compress
        if ($PSCmdlet.ShouldProcess($state.name, 'Invoke undocumented certificate enable transition')) {
            Invoke-MgGraphRequest -Method PATCH -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$($state.id)" -Body $body -ContentType 'application/json' | Out-Null
            $manualStep = 'Verify the undocumented enable transition in Entra admin center.'
        }
    }

    return [pscustomobject]@{
        Id         = $state.id
        Name       = $state.name
        Status     = $state.status
        Changed    = $true
        ManualStep = $manualStep
    }
}

Export-ModuleMember -Function @(
    'Assert-GsaRootCertificate',
    'ConvertFrom-GsaBase64Url',
    'ConvertTo-GsaBase64Url',
    'Get-GsaDerChild',
    'Get-GsaDerLength',
    'Get-GsaKeyVaultCertificate',
    'Get-OrCreateGsaRootCertificate',
    'Join-GsaSignedDer',
    'ConvertTo-GsaCrl',
    'ConvertTo-GsaSignedCertificate',
    'Publish-GsaCrl',
    'Set-GsaTlsCertificate'
)
