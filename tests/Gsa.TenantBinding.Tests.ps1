BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\scripts\modules\Gsa.Common.psm1') -Force
    $target = @{ subscriptionId = '11111111-1111-1111-1111-111111111111'; tenantId = '22222222-2222-2222-2222-222222222222' }
    $azureAccount = [pscustomobject]@{ id = $target.subscriptionId; tenantId = $target.tenantId }
    $graphContext = [pscustomobject]@{ TenantId = $target.tenantId }
}

Describe 'Azure and Graph tenant binding before GSA mutation' {
    It 'accepts the exact selected subscription and tenant' {
        { Assert-GsaTenantBinding -SubscriptionId $target.subscriptionId -AzureTenantId $target.tenantId -AzureAccount $azureAccount -GraphContext $graphContext } | Should -Not -Throw
    }

    It 'rejects a missing azd tenant rather than trusting cached Graph context' {
        { Assert-GsaTenantBinding -SubscriptionId $target.subscriptionId -AzureTenantId '' -AzureAccount $azureAccount -GraphContext $graphContext } | Should -Throw '*required*'
    }

    It 'rejects an Azure CLI account from another subscription or tenant' {
        $wrongSubscription = [pscustomobject]@{ id = '33333333-3333-3333-3333-333333333333'; tenantId = $target.tenantId }
        $wrongTenant = [pscustomobject]@{ id = $target.subscriptionId; tenantId = '33333333-3333-3333-3333-333333333333' }
        { Assert-GsaTenantBinding -SubscriptionId $target.subscriptionId -AzureTenantId $target.tenantId -AzureAccount $wrongSubscription -GraphContext $graphContext } | Should -Throw '*selected Azure CLI*'
        { Assert-GsaTenantBinding -SubscriptionId $target.subscriptionId -AzureTenantId $target.tenantId -AzureAccount $wrongTenant -GraphContext $graphContext } | Should -Throw '*selected Azure CLI*'
    }

    It 'rejects a cached Graph context from another tenant' {
        $otherGraph = [pscustomobject]@{ TenantId = '33333333-3333-3333-3333-333333333333' }
        { Assert-GsaTenantBinding -SubscriptionId $target.subscriptionId -AzureTenantId $target.tenantId -AzureAccount $azureAccount -GraphContext $otherGraph } | Should -Throw '*Graph tenant*'
    }
}
