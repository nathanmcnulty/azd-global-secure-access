#Requires -Version 7.6
function New-GsaTestCrl {
    param(
        [Parameter(Mandatory)][DateTimeOffset] $ThisUpdate,
        [AllowNull()][object] $NextUpdate,
        [switch] $UseGeneralizedTime
    )

    $rsa = [Security.Cryptography.RSA]::Create(2048)
    try {
        $tbsWriter = [Formats.Asn1.AsnWriter]::new([Formats.Asn1.AsnEncodingRules]::DER)
        $null = $tbsWriter.PushSequence()
        $null = $tbsWriter.PushSequence()
        $tbsWriter.WriteObjectIdentifier('1.2.840.113549.1.1.11')
        $tbsWriter.WriteNull()
        $tbsWriter.PopSequence()
        $issuer = [Security.Cryptography.X509Certificates.X500DistinguishedName]::new('CN=GSA Test CRL')
        $tbsWriter.WriteEncodedValue($issuer.RawData)
        if ($UseGeneralizedTime) { $tbsWriter.WriteGeneralizedTime($ThisUpdate, $true) }
        else { $tbsWriter.WriteUtcTime($ThisUpdate) }
        if ($null -ne $NextUpdate) {
            if ($UseGeneralizedTime) { $tbsWriter.WriteGeneralizedTime([DateTimeOffset]$NextUpdate, $true) }
            else { $tbsWriter.WriteUtcTime([DateTimeOffset]$NextUpdate) }
        }
        $tbsWriter.PopSequence()
        $tbs = $tbsWriter.Encode()
        $signature = $rsa.SignData(
            $tbs,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )

        $writer = [Formats.Asn1.AsnWriter]::new([Formats.Asn1.AsnEncodingRules]::DER)
        $null = $writer.PushSequence()
        $writer.WriteEncodedValue($tbs)
        $null = $writer.PushSequence()
        $writer.WriteObjectIdentifier('1.2.840.113549.1.1.11')
        $writer.WriteNull()
        $writer.PopSequence()
        $writer.WriteBitString($signature)
        $writer.PopSequence()
        return ,$writer.Encode()
    }
    finally {
        $rsa.Dispose()
    }
}
