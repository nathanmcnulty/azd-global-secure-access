#Requires -Version 7.6

BeforeAll {
    $script:previousBetaAcceptance = $env:GSA_ACCEPT_GRAPH_BETA_TERMS
    $env:GSA_ACCEPT_GRAPH_BETA_TERMS = 'true'
    function global:Get-MgContext { }
    function global:Connect-MgGraph { param($Scopes, $Environment, $TenantId, $ContextScope, [switch]$NoWelcome); $null = $Scopes, $Environment, $TenantId, $ContextScope, $NoWelcome }
    function global:Invoke-MgGraphRequest { param($Method, $Uri, $OutputType); $null = $Method, $Uri, $OutputType }
    Import-Module (Join-Path $PSScriptRoot '../scripts/modules/Gsa.Common.psm1') -Force
    $script:tenant = '11111111-1111-1111-1111-111111111111'
    $script:account = 'operator@example.com'
    $script:scopes = @('NetworkAccess.Read.All')
    function global:New-Context {
        param([string]$TenantId=$script:tenant, [string]$Account=$script:account,
        [string]$AuthType='Delegated', [string]$ContextScope='Process', [string[]]$Scopes=$script:scopes)
        [pscustomobject]@{ TenantId=$TenantId; Environment='Global'; Account=$Account; AuthType=$AuthType; ContextScope=$ContextScope; Scopes=$Scopes }
    }
}

AfterAll {
    $env:GSA_ACCEPT_GRAPH_BETA_TERMS = $script:previousBetaAcceptance
    Remove-Item Function:\global:Get-MgContext, Function:\global:Connect-MgGraph, Function:\global:Invoke-MgGraphRequest, Function:\global:New-Context -ErrorAction SilentlyContinue
}

Describe 'GSA delegated Graph account and usability preflight' {
    BeforeEach {
        Mock -ModuleName Gsa.Common Connect-MgGraph
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest { [pscustomobject]@{ value=@() } }
        Mock -ModuleName Gsa.Common Get-MgContext { New-Context }
    }

    It 'requires beta acceptance before inspecting context, login or the fixed read' {
        $env:GSA_ACCEPT_GRAPH_BETA_TERMS = 'false'
        try {
            { Connect-GsaGraph -Scopes $scopes -TenantId $tenant -ExpectedAccount $account -AllowInteractive:$true } |
                Should -Throw '*GSA_ACCEPT_GRAPH_BETA_TERMS*'
            Should -Invoke -ModuleName Gsa.Common Get-MgContext -Times 0 -Exactly
            Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
            Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
        } finally {
            $env:GSA_ACCEPT_GRAPH_BETA_TERMS = 'true'
        }
    }

    It 'rejects a missing or malformed expected UPN before inspecting context or Graph' -TestCases @(
        @{ Value = $null }
        @{ Value = '' }
        @{ Value = 'operator' }
        @{ Value = 'operator example.com' }
    ) {
        param($Value)
        $expectedAccount = [string]$Value
        { Connect-GsaGraph -Scopes $scopes -Environment Global -TenantId $tenant -ExpectedAccount $expectedAccount } | Should -Throw '*ExpectedAccount*'
        Should -Invoke -ModuleName Gsa.Common Get-MgContext -Times 0 -Exactly
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'reuses a matching delegated <Scope> context and performs exactly one fixed probe' -TestCases @(
        @{ Scope = 'Process' }
        @{ Scope = 'CurrentUser' }
    ) {
        param($Scope)
        $script:testContext = New-Context -ContextScope $Scope
        Mock -ModuleName Gsa.Common Get-MgContext { $script:testContext }
        Connect-GsaGraph -Scopes $scopes -Environment Global -TenantId $tenant -ExpectedAccount $account | Should -Not -BeNullOrEmpty
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Method -eq 'GET' -and $Uri -eq '/beta/networkAccess/forwardingProfiles' }
    }

    It 'rejects a wrong account before login or probe' {
        $script:testContext = [pscustomobject]@{ TenantId=$tenant; Environment='Global'; Account='other@example.com'; AuthType='Delegated'; ContextScope='Process'; Scopes=$scopes }
        Mock -ModuleName Gsa.Common Get-MgContext { $script:testContext }
        { Connect-GsaGraph -Scopes $scopes -Environment Global -TenantId $tenant -ExpectedAccount $account -AllowInteractive:$true } | Should -Throw
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'rejects an app-only context before login or probe' {
        $script:testContext = [pscustomobject]@{ TenantId=$tenant; Environment='Global'; Account=$account; AuthType='AppOnly'; ContextScope='Process'; Scopes=$scopes }
        Mock -ModuleName Gsa.Common Get-MgContext { $script:testContext }
        { Connect-GsaGraph -Scopes $scopes -Environment Global -TenantId $tenant -ExpectedAccount $account -AllowInteractive:$true } | Should -Throw
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'denies missing context without interactive authorization' {
        Mock -ModuleName Gsa.Common Get-MgContext { $null }
        { Connect-GsaGraph -Scopes $scopes -Environment Global -TenantId $tenant -ExpectedAccount $account } | Should -Throw '*interactive authentication is not authorized*'
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
    }

    It 'connects once when interactive authorization is explicit, then revalidates the actor and probes' {
        $script:reads = 0
        Mock -ModuleName Gsa.Common Get-MgContext {
            $script:reads++
            if ($script:reads -eq 1) { return $null }
            New-Context -ContextScope CurrentUser
        }
        Connect-GsaGraph -Scopes $scopes -Environment Global -TenantId $tenant -ExpectedAccount $account -AllowInteractive:$true | Should -Not -BeNullOrEmpty
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
            $TenantId -eq $tenant -and $Environment -eq 'Global' -and $ContextScope -eq 'CurrentUser' -and
            @($Scopes).Count -eq 1 -and $Scopes[0] -eq 'NetworkAccess.Read.All' -and $NoWelcome
        }
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 1 -Exactly
    }

    It 'fails after a probe error without retrying login' {
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest { throw [System.Exception]::new('provider detail CANARY') }
        { Connect-GsaGraph -Scopes $scopes -Environment Global -TenantId $tenant -ExpectedAccount $account -AllowInteractive:$true } | Should -Throw '*read-only usability probe*'
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 1 -Exactly
    }

    It 'rejects a malformed cached <Field> before login or probe' -TestCases @(
        @{ Field = 'AuthType'; Value = 'Unknown' }
        @{ Field = 'ContextScope'; Value = 'Unknown' }
        @{ Field = 'ContextScope'; Value = '' }
        @{ Field = 'Account'; Value = '' }
    ) {
        param($Field, $Value)
        $script:testContext = New-Context
        $script:testContext.$Field = $Value
        Mock -ModuleName Gsa.Common Get-MgContext { $script:testContext }
        { Connect-GsaGraph -Scopes $scopes -TenantId $tenant -ExpectedAccount $account -AllowInteractive:$true } | Should -Throw
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'rejects a post-login <Field> mismatch before the probe' -TestCases @(
        @{ Field = 'Account'; Value = 'other@example.com' }
        @{ Field = 'AuthType'; Value = 'AppOnly' }
        @{ Field = 'ContextScope'; Value = 'Process' }
        @{ Field = 'ContextScope'; Value = 'Unknown' }
    ) {
        param($Field, $Value)
        $script:testContext = New-Context -ContextScope CurrentUser
        $script:testContext.$Field = $Value
        $script:reads = 0
        Mock -ModuleName Gsa.Common Get-MgContext {
            $script:reads++
            if ($script:reads -eq 1) { return $null }
            $script:testContext
        }
        { Connect-GsaGraph -Scopes $scopes -TenantId $tenant -ExpectedAccount $account -AllowInteractive:$true } | Should -Throw
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 1 -Exactly
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'denies scope expansion without explicit interactive authorization' {
        $script:testContext = New-Context -Scopes @('Other.Scope')
        Mock -ModuleName Gsa.Common Get-MgContext { $script:testContext }
        { Connect-GsaGraph -Scopes $scopes -TenantId $tenant -ExpectedAccount $account } | Should -Throw
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }
}
