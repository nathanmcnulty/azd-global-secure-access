#Requires -Version 7.6

BeforeAll {
    $script:previousBetaAcceptance = $env:GSA_ACCEPT_GRAPH_BETA_TERMS
    $env:GSA_ACCEPT_GRAPH_BETA_TERMS = 'true'
    $root = Split-Path $PSScriptRoot -Parent
    function global:Get-MgContext { [CmdletBinding()] param() }
    function global:Connect-MgGraph {
        [CmdletBinding()]
        param(
            [string[]]$Scopes,
            [string]$Environment,
            [string]$TenantId,
            [string]$ContextScope,
            [string]$ErrorAction,
            [switch]$NoWelcome
        )
    }
    function global:Invoke-MgGraphRequest {
        [CmdletBinding()]
        param(
            [string]$Method,
            [string]$Uri,
            [string]$OutputType,
            [hashtable]$Headers,
            [object]$Body,
            [string]$ContentType
        )
    }
    Import-Module (Join-Path $root 'scripts/modules/Gsa.Common.psm1') -Force
    $targetTenant = '11111111-1111-1111-1111-111111111111'
    $foreignTenant = '22222222-2222-2222-2222-222222222222'
    $bindingTarget = @{ subscriptionId = '33333333-3333-3333-3333-333333333333'; tenantId = $targetTenant }
    $azureAccount = [pscustomobject]@{ id = $bindingTarget.subscriptionId; tenantId = $bindingTarget.tenantId }
    $graphContext = [pscustomobject]@{ TenantId = $bindingTarget.tenantId }
}

AfterAll {
    $env:GSA_ACCEPT_GRAPH_BETA_TERMS = $script:previousBetaAcceptance
    Remove-Item Function:\global:Get-MgContext -ErrorAction SilentlyContinue
    Remove-Item Function:\global:Connect-MgGraph -ErrorAction SilentlyContinue
    Remove-Item Function:\global:Invoke-MgGraphRequest -ErrorAction SilentlyContinue
}

Describe 'Azure and Graph tenant binding before GSA mutation' {
    It 'accepts the exact selected subscription and tenant' {
        { Assert-GsaTenantBinding -SubscriptionId $bindingTarget.subscriptionId -AzureTenantId $bindingTarget.tenantId -AzureAccount $azureAccount -GraphContext $graphContext } | Should -Not -Throw
    }

    It 'rejects a missing azd tenant rather than trusting cached Graph context' {
        { Assert-GsaTenantBinding -SubscriptionId $bindingTarget.subscriptionId -AzureTenantId '' -AzureAccount $azureAccount -GraphContext $graphContext } | Should -Throw '*required*'
    }

    It 'rejects an Azure CLI account from another subscription or tenant' {
        $wrongSubscription = [pscustomobject]@{ id = $foreignTenant; tenantId = $bindingTarget.tenantId }
        $wrongTenant = [pscustomobject]@{ id = $bindingTarget.subscriptionId; tenantId = $foreignTenant }
        { Assert-GsaTenantBinding -SubscriptionId $bindingTarget.subscriptionId -AzureTenantId $bindingTarget.tenantId -AzureAccount $wrongSubscription -GraphContext $graphContext } | Should -Throw '*selected Azure CLI*'
        { Assert-GsaTenantBinding -SubscriptionId $bindingTarget.subscriptionId -AzureTenantId $bindingTarget.tenantId -AzureAccount $wrongTenant -GraphContext $graphContext } | Should -Throw '*selected Azure CLI*'
    }

    It 'rejects a cached Graph context from another tenant' {
        $otherGraph = [pscustomobject]@{ TenantId = $foreignTenant }
        { Assert-GsaTenantBinding -SubscriptionId $bindingTarget.subscriptionId -AzureTenantId $bindingTarget.tenantId -AzureAccount $azureAccount -GraphContext $otherGraph } | Should -Throw '*Graph tenant*'
    }
}

Describe 'Explicit Microsoft Graph tenant binding' {
    BeforeEach {
        Mock -ModuleName Gsa.Common Connect-MgGraph { throw 'must not connect unless explicitly asserted' }
        Mock -ModuleName Gsa.Common Invoke-MgGraphRequest { [pscustomobject]@{ value=@() } }
    }

    It 'rejects an invalid target before reading or changing Graph context' -TestCases @(
        @{ Target = $null; Label = 'missing' }
        @{ Target = ''; Label = 'empty' }
        @{ Target = ' '; Label = 'whitespace' }
        @{ Target = 'CANARY_MALFORMED_TENANT'; Label = 'malformed' }
        @{ Target = '00000000-0000-0000-0000-000000000000'; Label = 'zero' }
    ) {
        param($Target, $Label)

        Mock -ModuleName Gsa.Common Get-MgContext { throw 'must not inspect context' }
        $message = $null
        try { Connect-GsaGraph -Scopes 'Scope.One' -Environment Global -TenantId $Target -ExpectedAccount 'operator@example.com' } catch { $message = $_.Exception.Message }

        $message | Should -BeExactly 'A valid target Azure tenant ID is required before Microsoft Graph authentication.' -Because $Label
        $message | Should -Not -Match 'CANARY_'
        Should -Invoke -ModuleName Gsa.Common Get-MgContext -Times 0 -Exactly
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'refuses a cached tenant mismatch before login even when scopes are missing' {
        Mock -ModuleName Gsa.Common Get-MgContext {
            [pscustomobject]@{ TenantId = $foreignTenant; Environment = 'Global'; Account='operator@example.com'; AuthType='Delegated'; ContextScope='CurrentUser'; Scopes = @() }
        }

        { Connect-GsaGraph -Scopes 'Scope.One' -Environment Global -TenantId $targetTenant -ExpectedAccount 'operator@example.com' } |
            Should -Throw -ExpectedMessage 'The current Microsoft Graph context does not match the required tenant and cloud.'
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'refuses a cached cloud mismatch before login even when scopes are missing' {
        Mock -ModuleName Gsa.Common Get-MgContext {
            [pscustomobject]@{ TenantId = $targetTenant; Environment = 'USGov'; Account='operator@example.com'; AuthType='Delegated'; ContextScope='CurrentUser'; Scopes = @() }
        }

        { Connect-GsaGraph -Scopes 'Scope.One' -Environment Global -TenantId $targetTenant -ExpectedAccount 'operator@example.com' } |
            Should -Throw -ExpectedMessage 'The current Microsoft Graph context does not match the required tenant and cloud.'
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
    }

    It 'refuses a malformed cached context instead of replacing it' -TestCases @(
        @{ Context = [pscustomobject]@{} }
        @{ Context = [pscustomobject]@{ TenantId = 'not-a-guid'; Environment = 'Global'; Account='operator@example.com'; AuthType='Delegated'; ContextScope='CurrentUser'; Scopes = @('Scope.One') } }
        @{ Context = [pscustomobject]@{ TenantId = '11111111-1111-1111-1111-111111111111'; Environment = 'Global'; Account='operator@example.com'; AuthType='Delegated'; ContextScope='CurrentUser'; Scopes = 'Scope.One' } }
    ) {
        param($Context)

        Mock -ModuleName Gsa.Common Get-MgContext { $Context }
        { Connect-GsaGraph -Scopes 'Scope.One' -Environment Global -TenantId $targetTenant -ExpectedAccount 'operator@example.com' } |
            Should -Throw -ExpectedMessage 'Microsoft Graph context validation failed.'
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
    }

    It 'reuses a matching tenant, cloud, and scope context' {
        $context = [pscustomobject]@{ TenantId = $targetTenant; Environment = 'Global'; Account='operator@example.com'; AuthType='Delegated'; ContextScope='CurrentUser'; Scopes = @('Scope.One') }
        Mock -ModuleName Gsa.Common Get-MgContext { $context }

        $result = Connect-GsaGraph -Scopes 'Scope.One' -Environment Global -TenantId $targetTenant -ExpectedAccount 'operator@example.com'
        [object]::ReferenceEquals($result, $context) | Should -BeTrue
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 0 -Exactly
    }

    It 'passes the normalized target tenant when no cached context exists' {
        $script:contextRead = 0
        Mock -ModuleName Gsa.Common Get-MgContext {
            $script:contextRead++
            if ($script:contextRead -eq 1) { return $null }
            [pscustomobject]@{ TenantId = $targetTenant; Environment = 'Global'; Account='operator@example.com'; AuthType='Delegated'; ContextScope='CurrentUser'; Scopes = @('Scope.One') }
        }
        Mock -ModuleName Gsa.Common Connect-MgGraph {}

        $result = Connect-GsaGraph -Scopes 'Scope.One' -Environment Global -TenantId "{$targetTenant}" -ExpectedAccount 'operator@example.com' -AllowInteractive:$true
        $result.TenantId | Should -BeExactly $targetTenant
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
            $TenantId -ceq $targetTenant -and $Environment -ceq 'Global' -and
            @($Scopes).Count -eq 1 -and $Scopes[0] -ceq 'Scope.One' -and $NoWelcome
        }
    }

    It 'passes the exact target tenant when expanding scopes on a matching context' {
        $script:contextRead = 0
        Mock -ModuleName Gsa.Common Get-MgContext {
            $script:contextRead++
            if ($script:contextRead -eq 1) {
                return [pscustomobject]@{ TenantId = $targetTenant; Environment = 'Global'; Account='operator@example.com'; AuthType='Delegated'; ContextScope='CurrentUser'; Scopes = @('Scope.One') }
            }
            [pscustomobject]@{ TenantId = $targetTenant; Environment = 'Global'; Account='operator@example.com'; AuthType='Delegated'; ContextScope='CurrentUser'; Scopes = @('Scope.One', 'Scope.Two') }
        }
        Mock -ModuleName Gsa.Common Connect-MgGraph {}

        $result = Connect-GsaGraph -Scopes @('Scope.One', 'Scope.Two') -Environment Global -TenantId $targetTenant -ExpectedAccount 'operator@example.com' -AllowInteractive:$true
        $result.Scopes | Should -Contain 'Scope.Two'
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
            $TenantId -ceq $targetTenant -and $Environment -ceq 'Global'
        }
    }

    It 'fails closed when post-login context is null' {
        Mock -ModuleName Gsa.Common Get-MgContext { $null }
        Mock -ModuleName Gsa.Common Connect-MgGraph {}

        { Connect-GsaGraph -Scopes 'Scope.One' -Environment Global -TenantId $targetTenant -ExpectedAccount 'operator@example.com' -AllowInteractive:$true } |
            Should -Throw -ExpectedMessage 'Microsoft Graph authentication did not return the required tenant and cloud.'
        Should -Invoke -ModuleName Gsa.Common Connect-MgGraph -Times 1 -Exactly
    }

    It 'fails closed when post-login context has another tenant' {
        $script:contextRead = 0
        Mock -ModuleName Gsa.Common Get-MgContext {
            $script:contextRead++
            if ($script:contextRead -eq 1) { return $null }
            [pscustomobject]@{ TenantId = $foreignTenant; Environment = 'Global'; Account='operator@example.com'; AuthType='Delegated'; ContextScope='CurrentUser'; Scopes = @('Scope.One') }
        }
        Mock -ModuleName Gsa.Common Connect-MgGraph {}

        { Connect-GsaGraph -Scopes 'Scope.One' -Environment Global -TenantId $targetTenant -ExpectedAccount 'operator@example.com' -AllowInteractive:$true } |
            Should -Throw -ExpectedMessage 'Microsoft Graph authentication did not return the required tenant and cloud.'
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'fails closed when post-login context has another cloud' {
        $script:contextRead = 0
        Mock -ModuleName Gsa.Common Get-MgContext {
            $script:contextRead++
            if ($script:contextRead -eq 1) { return $null }
            [pscustomobject]@{ TenantId = $targetTenant; Environment = 'USGov'; Account='operator@example.com'; AuthType='Delegated'; ContextScope='CurrentUser'; Scopes = @('Scope.One') }
        }
        Mock -ModuleName Gsa.Common Connect-MgGraph {}

        { Connect-GsaGraph -Scopes 'Scope.One' -Environment Global -TenantId $targetTenant -ExpectedAccount 'operator@example.com' -AllowInteractive:$true } |
            Should -Throw -ExpectedMessage 'Microsoft Graph authentication did not return the required tenant and cloud.'
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'fails closed when post-login context still lacks consented scopes' {
        $script:contextRead = 0
        Mock -ModuleName Gsa.Common Get-MgContext {
            $script:contextRead++
            if ($script:contextRead -eq 1) { return $null }
            [pscustomobject]@{ TenantId = $targetTenant; Environment = 'Global'; Account='operator@example.com'; AuthType='Delegated'; ContextScope='CurrentUser'; Scopes = @() }
        }
        Mock -ModuleName Gsa.Common Connect-MgGraph {}

        { Connect-GsaGraph -Scopes 'Scope.One' -Environment Global -TenantId $targetTenant -ExpectedAccount 'operator@example.com' -AllowInteractive:$true } |
            Should -Throw -ExpectedMessage 'Microsoft Graph consent is missing: Scope.One.'
        Should -Invoke -ModuleName Gsa.Common Invoke-MgGraphRequest -Times 0 -Exactly
    }
}

Describe 'Readiness entrypoint tenant target' {
    It 'records a tenant-consistency failure and performs no Graph dispatch when the target is absent' {
        $fixture = Join-Path $PSScriptRoot 'helpers/Invoke-GsaCrlReadinessFixture.ps1'
        $nativeOutput = & (Get-Process -Id $PID).Path -NoProfile -File $fixture -Case missingTenant -Root $root 2>&1

        $LASTEXITCODE | Should -Be 1
        $text = $nativeOutput | Out-String
        $text | Should -Not -Match 'FORBIDDEN_DISPATCH|CANARY_'
        $summary = $text | ConvertFrom-Json -Depth 40
        $summary.tenantId | Should -BeNullOrEmpty
        $tenantChecks = @($summary.checks | Where-Object name -eq 'Tenant consistency')
        $tenantChecks | Should -HaveCount 1
        $tenantChecks[0].status | Should -BeExactly 'Fail'
        $tenantChecks[0].detail | Should -BeExactly 'A valid AZURE_TENANT_ID is required before Microsoft Graph authentication.'
        @($tenantChecks | Where-Object status -eq 'Pass') | Should -HaveCount 0
    }
}

Describe 'Post-provision Azure binding order' {
    It 'rejects an Azure <case> before Graph connection or dispatch' -TestCases @(
        @{ case = 'subscriptionMismatch' }
        @{ case = 'tenantMismatch' }
    ) {
        param($case)

        $fixture = Join-Path $PSScriptRoot 'helpers/Invoke-GsaPostProvisionBindingFixture.ps1'
        $nativeOutput = & (Get-Process -Id $PID).Path -NoProfile -File $fixture -Case $case -Root $root 2>&1

        $LASTEXITCODE | Should -Be 0
        $text = $nativeOutput | Out-String
        $text | Should -Not -Match 'FORBIDDEN_'
        $result = $text | ConvertFrom-Json
        $result.failure | Should -BeExactly 'The selected Azure CLI subscription or tenant does not match the azd target.'
        $result.graphConnects | Should -Be 0
        $result.graphReads | Should -Be 0
    }
}
