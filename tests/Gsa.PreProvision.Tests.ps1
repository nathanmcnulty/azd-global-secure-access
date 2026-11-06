#Requires -Version 7.6
BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    $fixture = Join-Path $PSScriptRoot 'helpers/Invoke-GsaPreProvisionFixture.ps1'
    function Invoke-PreProvisionFixture {
        param([string[]]$Arguments = @())
        $output = & (Get-Process -Id $PID).Path -NoProfile -File $fixture -Root $root @Arguments 2>&1
        $LASTEXITCODE | Should -Be 0
        $result = ($output | Out-String) | ConvertFrom-Json
        $result.cloudReads | Should -Be 1
        return $result
    }
}

Describe 'Default foundation preprovision gates' {
    It 'accepts the packaged safe defaults without Graph beta acceptance' {
        (Invoke-PreProvisionFixture).failure | Should -BeNullOrEmpty
    }
    It 'accepts absent forwarding selections without Graph beta acceptance' {
        (Invoke-PreProvisionFixture -Arguments @('-EmptyProfiles')).failure | Should -BeNullOrEmpty
    }
    It 'accepts case-insensitive Unchanged forwarding values' {
        (Invoke-PreProvisionFixture -Arguments @('-LowercaseProfiles')).failure | Should -BeNullOrEmpty
    }
    It 'still gates <state> for <profile> on beta acceptance' -TestCases @(
        @{ profile = 'GSA_M365_PROFILE_STATE'; state = 'Enabled' }
        @{ profile = 'GSA_M365_PROFILE_STATE'; state = 'Disabled' }
        @{ profile = 'GSA_PRIVATE_PROFILE_STATE'; state = 'Enabled' }
        @{ profile = 'GSA_PRIVATE_PROFILE_STATE'; state = 'Disabled' }
        @{ profile = 'GSA_INTERNET_PROFILE_STATE'; state = 'Enabled' }
        @{ profile = 'GSA_INTERNET_PROFILE_STATE'; state = 'Disabled' }
    ) {
        param($profile, $state)
        $result = Invoke-PreProvisionFixture -Arguments @('-ProfileName', $profile, '-ProfileState', $state)
        $result.failure | Should -BeLike '*Set GSA_ACCEPT_GRAPH_BETA_TERMS=true*'
    }
    It 'still gates the explicit Graph feature <feature>' -TestCases @(
        @{ feature = 'GSA_ENABLE_TENANT_ONBOARDING' }
        @{ feature = 'GSA_ENABLE_QUICK_ACCESS' }
        @{ feature = 'GSA_ENABLE_PRIVATE_ACCESS_APP' }
        @{ feature = 'GSA_ENABLE_TLS_INSPECTION' }
        @{ feature = 'GSA_ENABLE_INTERNET_BASELINE' }
    ) {
        param($feature)
        (Invoke-PreProvisionFixture -Arguments @('-FeatureName', $feature)).failure |
            Should -BeLike '*Set GSA_ACCEPT_GRAPH_BETA_TERMS=true*'
    }
    It 'accepts an explicitly beta-approved <state> forwarding selection' -TestCases @(
        @{ state = 'Enabled' }
        @{ state = 'Disabled' }
    ) {
        param($state)
        (Invoke-PreProvisionFixture -Arguments @('-ProfileState', $state, '-AcceptBeta')).failure |
            Should -BeNullOrEmpty
    }
    It 'rejects an invalid forwarding state before treating it as a feature request' {
        $result = Invoke-PreProvisionFixture -Arguments @('-ProfileState', 'not-a-state')
        $result.failure | Should -BeExactly 'GSA_M365_PROFILE_STATE must be Enabled, Disabled, or Unchanged.'
    }
}
