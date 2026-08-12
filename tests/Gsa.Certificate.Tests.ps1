BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\scripts\modules\Gsa.Certificate.psm1') -Force

    $script:issuerKey = [System.Security.Cryptography.RSA]::Create(4096)
    $rootRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Offline GSA Root,O=Contoso',
        $script:issuerKey,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $rootRequest.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
    )
    $usage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
    $rootRequest.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($usage, $true)
    )
    $rootRequest.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($rootRequest.PublicKey, $false)
    )
    $script:root = $rootRequest.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddDays(-1),
        [DateTimeOffset]::UtcNow.AddYears(10)
    )
    $script:issuer = [pscustomobject]@{
        Certificate = $script:root
        KeyId       = 'https://offline.test/keys/root/version'
        Pem         = $script:root.ExportCertificatePem()
        Thumbprint  = $script:root.Thumbprint
    }
}

AfterAll {
    $script:root.Dispose()
    $script:issuerKey.Dispose()
}

Describe 'Offline certificate reconstruction' {
    BeforeEach {
        Mock -ModuleName Gsa.Certificate Invoke-GsaKeyVaultSign {
            param($KeyId, $Hash)
            return $script:issuerKey.SignHash(
                $Hash,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
        }
    }

    It 'builds a verifiable GSA CA with pathLen 1, serverAuth, and a CDP' {
        $childKey = [System.Security.Cryptography.RSA]::Create(2048)
        try {
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Offline GSA CA,O=Contoso',
                $childKey,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $result = ConvertTo-GsaSignedCertificate `
                -CsrPem $request.CreateSigningRequestPem() `
                -Issuer $script:issuer `
                -CrlUrl 'http://crl.example.test/gsa.crl'

            $basic = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension](
                $result.Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
            )
            $eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension](
                $result.Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
            )
            $basic.CertificateAuthority | Should -BeTrue
            $basic.HasPathLengthConstraint | Should -BeTrue
            $basic.PathLengthConstraint | Should -Be 1
            @($eku.EnhancedKeyUsages.Value) | Should -Contain '1.3.6.1.5.5.7.3.1'
            @($result.Certificate.Extensions.Oid.Value) | Should -Contain '2.5.29.31'
        } finally {
            $childKey.Dispose()
        }
    }

    It 'builds a signed CRL with a large monotonic number' {
        $crl = ConvertTo-GsaCrl -Issuer $script:issuer -Number ([System.Numerics.BigInteger]::Parse('1234567890123'))
        $crl.Length | Should -BeGreaterThan 500
        $crl[0] | Should -Be 0x30
    }
}
