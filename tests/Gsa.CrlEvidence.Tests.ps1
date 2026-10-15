#Requires -Version 7.6
BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $root 'scripts/modules/Gsa.Readiness.psm1') -Force
    $hash = 'A' * 64
    $now = [DateTimeOffset]'2026-10-11T00:00:00Z'
    function New-CrlObservation {
        [pscustomobject]@{ published = $true; expectedSha256 = $hash; actualSha256 = $hash; nextUpdate = '2026-11-11T00:00:00Z' }
    }
}
Describe 'Closed CRL publication and committed-date evidence' {
    It 'keeps exact byte publication distinct from unobserved expiry' {
        $result = Test-GsaCrlReadiness -CrlState (New-CrlObservation) -Now $now
        $result.Status | Should -Be 'Warning'
        $result.Actual.publicationVerified | Should -BeTrue
        $result.Actual.nextUpdateSource | Should -BeExactly 'committedState'
        $result.Actual.nextUpdate | Should -BeExactly '2026-11-11T00:00:00.0000000+00:00'
        $result.Actual.expiryObserved | Should -BeFalse
        $result.Actual.observedNextUpdate | Should -BeNullOrEmpty
        $result.Detail | Should -Not -Match 'valid through'
    }
    It 'derives hash equality instead of trusting the caller flag' {
        $state = New-CrlObservation
        $state.actualSha256 = 'B' * 64
        $state | Add-Member hashMatches $true
        $result = Test-GsaCrlReadiness -CrlState $state -Now $now
        $result.Status | Should -Be 'Fail'
        $result.Actual.hashMatches | Should -BeFalse
        $result.Actual.publicationVerified | Should -BeFalse
        $result.Actual.failureCode | Should -BeExactly 'HashMismatch'
    }
    It 'normalizes valid digest case and ignores a false flag' {
        $state = New-CrlObservation
        $state.actualSha256 = $hash.ToLowerInvariant()
        $state | Add-Member hashMatches $false
        (Test-GsaCrlReadiness -CrlState $state -Now $now).Actual.publicationVerified | Should -BeTrue
    }
    It 'refuses invalid hash evidence <name>' -ForEach @(
        @{ name='missing'; value=$null }, @{ name='empty'; value='' }, @{ name='short'; value='A'*63 },
        @{ name='long'; value='A'*65 }, @{ name='terminal LF'; value=('A'*64)+"`n" },
        @{ name='nonhex'; value='Z'*64 }, @{ name='object'; value=@{ url='CANARY_URL' } }
    ) {
        foreach ($field in @('expectedSha256', 'actualSha256')) {
            $state = New-CrlObservation
            $state.$field = $value
            $result = Test-GsaCrlReadiness -CrlState $state -Now $now
            $result.Status | Should -Be 'Fail'
            $result.Actual.publicationVerified | Should -BeFalse
            $result.Actual.failureCode | Should -BeExactly 'HashEvidenceInvalid'
        }
    }
    It 'qualifies recorded date <name> without observed expiry' -ForEach @(
        @{ name='expired'; value='2026-10-10T00:00:00Z'; code='CommittedExpiryExpired'; status='Fail' },
        @{ name='near'; value='2026-10-14T00:00:00Z'; code='CommittedExpiryNear'; status='Warning' },
        @{ name='missing'; value=$null; code='CommittedExpiryMissing'; status='Warning' },
        @{ name='invalid'; value='CANARY_DATE'; code='CommittedExpiryInvalid'; status='Warning' },
        @{ name='bad calendar'; value='2026-02-30T00:00:00Z'; code='CommittedExpiryInvalid'; status='Warning' },
        @{ name='no timezone'; value='2026-11-11T00:00:00'; code='CommittedExpiryInvalid'; status='Warning' },
        @{ name='control'; value="2026-11-11T00:00:00Z`n"; code='CommittedExpiryInvalid'; status='Warning' }
    ) {
        $state = New-CrlObservation
        $state.nextUpdate = $value
        $result = Test-GsaCrlReadiness -CrlState $state -Now $now
        $result.Status | Should -Be $status
        $result.Actual.failureCode | Should -BeExactly $code
        $result.Actual.expiryObserved | Should -BeFalse
    }
    It 'requires a typed publication observation' {
        $state = New-CrlObservation
        $state.published = 'true'
        $result = Test-GsaCrlReadiness -CrlState $state -Now $now
        $result.Status | Should -Be 'Fail'
        $result.Actual.published | Should -BeFalse
    }
    It 'does not treat a caller date string alone as decoded DER evidence' {
        $state = New-CrlObservation
        $state | Add-Member observedThisUpdate '2026-10-01T00:00:00Z'
        $state | Add-Member observedNextUpdate '2026-11-01T00:00:00Z'
        $result = Test-GsaCrlReadiness -CrlState $state -Now $now
        $result.Actual.expiryObserved | Should -BeFalse
        $result.Actual.failureCode | Should -BeExactly 'ObservedExpiryUnknown'
    }
    It 'uses decoded observed expiry instead of a future committed advisory date' {
        $state = New-CrlObservation
        $state | Add-Member derDecoded $true
        $state | Add-Member observedThisUpdate '2026-09-01T00:00:00Z'
        $state | Add-Member observedNextUpdate '2026-10-10T00:00:00Z'
        $result = Test-GsaCrlReadiness -CrlState $state -Now $now
        $result.Status | Should -BeExactly 'Fail'
        $result.Actual.failureCode | Should -BeExactly 'ObservedExpiryExpired'
        $result.Actual.nextUpdate | Should -BeExactly '2026-11-11T00:00:00.0000000+00:00'
        $result.Actual.expiryObserved | Should -BeTrue
    }
    It 'omits unknown provider fields and leaves its input unchanged' {
        $state = New-CrlObservation
        $state.published = $false
        $state | Add-Member url 'http://CANARY_URL.invalid/?sig=CANARY_SIG'
        $state | Add-Member error 'CANARY_PROVIDER bearer CANARY_TOKEN'
        $state | Add-Member extra @{ nested='CANARY_MEMBER' }
        $before = $state | ConvertTo-Json -Depth 20
        $result = Test-GsaCrlReadiness -CrlState $state -Now $now
        ($result | ConvertTo-Json -Depth 20) | Should -Not -Match 'CANARY_'
        ($state | ConvertTo-Json -Depth 20) | Should -BeExactly $before
        @($result.Actual.PSObject.Properties.Name).Count | Should -Be 13
        $result.Actual.signatureVerified | Should -BeFalse
        $result.Actual.issuerVerified | Should -BeFalse
    }
}
Describe 'Actual read-only entrypoint CRL byte observation' {
    It 'projects actual hashed bytes safely for <case>' -ForEach @(
        @{ case='matched' }, @{ case='mismatch' }, @{ case='failed' }, @{ case='wrongType' }, @{ case='absent' }, @{ case='emptyBaseline' }, @{ case='unrelatedBaseline' }, @{ case='noManifest' }, @{ case='emptyManifest' }
    ) {
        $fixture = Join-Path $PSScriptRoot 'helpers/Invoke-GsaCrlReadinessFixture.ps1'
        $nativeOutput = & (Get-Process -Id $PID).Path -NoProfile -File $fixture -Case $case -Root $root 2>&1
        $LASTEXITCODE | Should -Be 1 # Unsupported fixture cloud is deliberately a separate Fail.
        $text = $nativeOutput | Out-String
        $text | Should -Not -Match 'CANARY_|FORBIDDEN_DISPATCH'
        $summary = $text | ConvertFrom-Json -Depth 40
        $summary.ready | Should -BeFalse
        $crl = @($summary.checks | Where-Object name -eq 'CRL publication')
        if ($case -in @('absent','noManifest','emptyManifest')) { $crl.Count | Should -Be 0; return }
        $crl.Count | Should -Be 1
        if ($case -eq 'mismatch') {
            $crl[0].resourceKey | Should -BeExactly 'fixtureCrl'
            $crl[0].ownership | Should -BeExactly 'managed'
        } else {
            $crl[0].resourceKey | Should -BeNullOrEmpty
            $crl[0].ownership | Should -BeNullOrEmpty
        }
        if ($case -in @('matched','emptyBaseline','unrelatedBaseline')) {
            $crl[0].actual.publicationVerified | Should -BeTrue
            $crl[0].actual.actualSha256 | Should -BeExactly ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]](1,2,3,4))))
            $crl[0].actual.expiryObserved | Should -BeFalse
        } else {
            $crl[0].status | Should -Be 'Fail'
            $crl[0].actual.publicationVerified | Should -BeFalse
        }
    }
}
