BeforeAll {
    function Invoke-MgGraphRequest {}
    Import-Module (Join-Path $PSScriptRoot '..\scripts\modules\Gsa.Graph.psm1') -Force
}

AfterAll {
    Remove-Item Function:\Invoke-MgGraphRequest -ErrorAction SilentlyContinue
}

Describe 'GSA Internet Access baseline' {
    BeforeEach {
        $env:GSA_ACCEPT_GRAPH_BETA_TERMS = 'true'
        $script:posts = [System.Collections.Generic.List[object]]::new()

        Mock -ModuleName Gsa.Graph Get-GsaGraphCollection {
            param($Uri)
            return @()
        }
        Mock -ModuleName Gsa.Graph Invoke-MgGraphRequest {
            param($Method, $Uri, $Body)
            if ($Method -eq 'POST') {
                $payload = $Body | ConvertFrom-Json -Depth 20
                $script:posts.Add([pscustomobject]@{ Uri = $Uri; Body = $payload })
                switch ($Uri) {
                    '/beta/networkAccess/filteringPolicies' { return [pscustomobject]@{ id = 'policy-id'; name = $payload.name } }
                    '/beta/networkAccess/filteringProfiles' { return [pscustomobject]@{ id = 'profile-id'; name = $payload.name; state = 'enabled'; priority = 100 } }
                    '/beta/identity/conditionalAccess/policies' { return [pscustomobject]@{ id = 'ca-id'; displayName = $payload.displayName } }
                }
            }
        }
    }

    AfterEach {
        Remove-Item Env:\GSA_ACCEPT_GRAPH_BETA_TERMS -ErrorAction SilentlyContinue
    }

    It 'normalizes social media aliases to the documented category identifier' {
        InModuleScope Gsa.Graph {
            ConvertTo-GsaWebCategoryName 'Social Media' | Should -Be 'SocialNetworking'
            ConvertTo-GsaWebCategoryName 'social-networking' | Should -Be 'SocialNetworking'
        }
    }

    It 'creates a custom profile and a disabled unassigned Conditional Access policy' {
        $result = Set-GsaInternetBaseline -Name 'Baseline Filter' -BlockedCategories 'Social Media' -SecurityProfileName 'Baseline Profile' -ConditionalAccessPolicyName 'Baseline CA'

        $script:posts | Should -HaveCount 4
        $filterPost = $script:posts | Where-Object Uri -eq '/beta/networkAccess/filteringPolicies'
        $filterPost.Body.action | Should -Be 'block'
        $filterPost.Body.policyRules[0].destinations[0].name | Should -Be 'SocialNetworking'

        $profilePost = $script:posts | Where-Object Uri -eq '/beta/networkAccess/filteringProfiles'
        $profilePost.Body.state | Should -Be 'enabled'
        $profilePost.Body.priority | Should -Be 100

        $linkPost = $script:posts | Where-Object Uri -eq '/beta/networkAccess/filteringProfiles/profile-id/policies'
        $linkPost.Body.policy.id | Should -Be 'policy-id'
        $linkPost.Body.loggingState | Should -Be 'enabled'

        $caPost = $script:posts | Where-Object Uri -eq '/beta/identity/conditionalAccess/policies'
        $caPost.Body.state | Should -Be 'disabled'
        @($caPost.Body.conditions.users.includeUsers) | Should -HaveCount 0
        @($caPost.Body.conditions.users.includeGroups) | Should -HaveCount 0
        @($caPost.Body.conditions.users.includeRoles) | Should -HaveCount 0
        $caPost.Body.conditions.applications.includeApplications | Should -Be '5dc48733-b5df-475c-a49b-fa307ef00853'
        $caPost.Body.sessionControls.globalSecureAccessFilteringProfile.profileId | Should -Be 'profile-id'
        $caPost.Body.sessionControls.globalSecureAccessFilteringProfile.isEnabled | Should -BeTrue
        $result.ConditionalAccessState | Should -Be 'disabled'
        @($result.AssignedPrincipals) | Should -HaveCount 0
    }

    It 'reuses compatible objects without creating duplicates' {
        Mock -ModuleName Gsa.Graph Get-GsaGraphCollection {
            param($Uri)
            switch -Regex ($Uri) {
                '^/beta/networkAccess/filteringPolicies\?' { return @([pscustomobject]@{ id = 'policy-id'; name = 'Baseline Filter' }) }
                '^/beta/networkAccess/filteringProfiles\?' { return @([pscustomobject]@{ id = 'profile-id'; name = 'Baseline Profile'; state = 'enabled'; priority = 100 }) }
                '/filteringProfiles/profile-id/policies$' { return @([pscustomobject]@{ policy = [pscustomobject]@{ id = 'policy-id' }; priority = 100; state = 'enabled'; loggingState = 'enabled' }) }
                '^/beta/identity/conditionalAccess/policies\?' {
                    return @([pscustomobject]@{
                        id = 'ca-id'; displayName = 'Baseline CA'; state = 'disabled'
                        conditions = [pscustomobject]@{
                            applications = [pscustomobject]@{ includeApplications = @('5dc48733-b5df-475c-a49b-fa307ef00853') }
                            users = [pscustomobject]@{ includeUsers = @(); includeGroups = @(); includeRoles = @() }
                        }
                        sessionControls = [pscustomobject]@{ globalSecureAccessFilteringProfile = [pscustomobject]@{ profileId = 'profile-id'; isEnabled = $true } }
                    })
                }
                default { return @() }
            }
        }
        Mock -ModuleName Gsa.Graph Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -eq 'GET' -and $Uri -match '/filteringPolicies/policy-id') {
                return [pscustomobject]@{
                    id = 'policy-id'; name = 'Baseline Filter'; action = 'block'
                    policyRules = @([pscustomobject]@{
                        '@odata.type' = '#microsoft.graph.networkaccess.webCategoryFilteringRule'
                        ruleType = 'webCategory'
                        destinations = @([pscustomobject]@{ name = 'SocialNetworking' })
                    })
                }
            }
            throw "Unexpected request: $Method $Uri"
        }

        $result = Set-GsaInternetBaseline -Name 'Baseline Filter' -BlockedCategories 'SocialNetworking' -SecurityProfileName 'Baseline Profile' -ConditionalAccessPolicyName 'Baseline CA'

        Assert-MockCalled -ModuleName Gsa.Graph Invoke-MgGraphRequest -ParameterFilter { $Method -eq 'POST' } -Times 0
        $result.FilteringPolicyId | Should -Be 'policy-id'
        $result.SecurityProfileId | Should -Be 'profile-id'
        $result.ConditionalAccessPolicyId | Should -Be 'ca-id'
    }

    It 'fails safely when an existing Conditional Access policy has assignments' {
        Mock -ModuleName Gsa.Graph Get-GsaGraphCollection {
            param($Uri)
            switch -Regex ($Uri) {
                '^/beta/networkAccess/filteringPolicies\?' { return @([pscustomobject]@{ id = 'policy-id'; name = 'Baseline Filter' }) }
                '^/beta/networkAccess/filteringProfiles\?' { return @([pscustomobject]@{ id = 'profile-id'; name = 'Baseline Profile'; state = 'enabled'; priority = 100 }) }
                '/filteringProfiles/profile-id/policies$' { return @([pscustomobject]@{ policy = [pscustomobject]@{ id = 'policy-id' }; priority = 100; state = 'enabled'; loggingState = 'enabled' }) }
                '^/beta/identity/conditionalAccess/policies\?' {
                    return @([pscustomobject]@{
                        id = 'ca-id'; displayName = 'Baseline CA'; state = 'disabled'
                        conditions = [pscustomobject]@{
                            applications = [pscustomobject]@{ includeApplications = @('5dc48733-b5df-475c-a49b-fa307ef00853') }
                            users = [pscustomobject]@{ includeUsers = @('All'); includeGroups = @(); includeRoles = @() }
                        }
                        sessionControls = [pscustomobject]@{ globalSecureAccessFilteringProfile = [pscustomobject]@{ profileId = 'profile-id'; isEnabled = $true } }
                    })
                }
                default { return @() }
            }
        }
        Mock -ModuleName Gsa.Graph Invoke-MgGraphRequest {
            [pscustomobject]@{
                id = 'policy-id'; action = 'block'
                policyRules = @([pscustomobject]@{ ruleType = 'webCategory'; destinations = @([pscustomobject]@{ name = 'SocialNetworking' }) })
            }
        }

        { Set-GsaInternetBaseline -Name 'Baseline Filter' -BlockedCategories 'SocialNetworking' -SecurityProfileName 'Baseline Profile' -ConditionalAccessPolicyName 'Baseline CA' } |
            Should -Throw '*disabled, unassigned managed configuration*'
    }

    It 'reports clear drift when an existing Conditional Access policy lacks the filtering session control' {
        Mock -ModuleName Gsa.Graph Get-GsaGraphCollection {
            param($Uri)
            switch -Regex ($Uri) {
                '^/beta/networkAccess/filteringPolicies\?' { return @([pscustomobject]@{ id = 'policy-id'; name = 'Baseline Filter' }) }
                '^/beta/networkAccess/filteringProfiles\?' { return @([pscustomobject]@{ id = 'profile-id'; name = 'Baseline Profile'; state = 'enabled'; priority = 100 }) }
                '/filteringProfiles/profile-id/policies$' { return @([pscustomobject]@{ policy = [pscustomobject]@{ id = 'policy-id' }; priority = 100; state = 'enabled'; loggingState = 'enabled' }) }
                '^/beta/identity/conditionalAccess/policies\?' {
                    return @([pscustomobject]@{
                        id = 'ca-id'; displayName = 'Baseline CA'; state = 'disabled'
                        conditions = [pscustomobject]@{
                            applications = [pscustomobject]@{ includeApplications = @('5dc48733-b5df-475c-a49b-fa307ef00853') }
                            users = [pscustomobject]@{ includeUsers = @(); includeGroups = @(); includeRoles = @() }
                        }
                    })
                }
                default { return @() }
            }
        }
        Mock -ModuleName Gsa.Graph Invoke-MgGraphRequest {
            [pscustomobject]@{
                id = 'policy-id'; action = 'block'
                policyRules = @([pscustomobject]@{ ruleType = 'webCategory'; destinations = @([pscustomobject]@{ name = 'SocialNetworking' }) })
            }
        }

        { Set-GsaInternetBaseline -Name 'Baseline Filter' -BlockedCategories 'SocialNetworking' -SecurityProfileName 'Baseline Profile' -ConditionalAccessPolicyName 'Baseline CA' } |
            Should -Throw '*disabled, unassigned managed configuration*'
    }

    It 'fails safely when a reused security profile contains unmanaged policy links' {
        Mock -ModuleName Gsa.Graph Get-GsaGraphCollection {
            param($Uri)
            switch -Regex ($Uri) {
                '^/beta/networkAccess/filteringPolicies\?' { return @([pscustomobject]@{ id = 'policy-id'; name = 'Baseline Filter' }) }
                '^/beta/networkAccess/filteringProfiles\?' { return @([pscustomobject]@{ id = 'profile-id'; name = 'Baseline Profile'; state = 'enabled'; priority = 100 }) }
                '/filteringProfiles/profile-id/policies$' {
                    return @(
                        [pscustomobject]@{ policy = [pscustomobject]@{ id = 'policy-id' }; priority = 100; state = 'enabled'; loggingState = 'enabled' },
                        [pscustomobject]@{ policy = [pscustomobject]@{ id = 'unmanaged-policy-id' }; priority = 200; state = 'enabled'; loggingState = 'enabled' }
                    )
                }
                default { return @() }
            }
        }
        Mock -ModuleName Gsa.Graph Invoke-MgGraphRequest {
            [pscustomobject]@{
                id = 'policy-id'; action = 'block'
                policyRules = @([pscustomobject]@{ ruleType = 'webCategory'; destinations = @([pscustomobject]@{ name = 'SocialNetworking' }) })
            }
        }

        { Set-GsaInternetBaseline -Name 'Baseline Filter' -BlockedCategories 'SocialNetworking' -SecurityProfileName 'Baseline Profile' -ConditionalAccessPolicyName 'Baseline CA' } |
            Should -Throw '*contains unmanaged policy links*'
    }

    It 'validates the complete baseline through the read-only readiness path' {
        Mock -ModuleName Gsa.Graph Get-GsaGraphCollection {
            param($Uri)
            switch -Regex ($Uri) {
                '^/beta/networkAccess/filteringPolicies\?' { return @([pscustomobject]@{ id = 'policy-id'; name = 'Baseline Filter' }) }
                '^/beta/networkAccess/filteringProfiles\?' { return @([pscustomobject]@{ id = 'profile-id'; name = 'Baseline Profile'; state = 'enabled'; priority = 100 }) }
                '/filteringProfiles/profile-id/policies$' { return @([pscustomobject]@{ policy = [pscustomobject]@{ id = 'policy-id' }; priority = 100; state = 'enabled'; loggingState = 'enabled' }) }
                '^/beta/identity/conditionalAccess/policies\?' {
                    return @([pscustomobject]@{
                        id = 'ca-id'; displayName = 'Baseline CA'; state = 'disabled'
                        conditions = [pscustomobject]@{
                            applications = [pscustomobject]@{ includeApplications = @('5dc48733-b5df-475c-a49b-fa307ef00853') }
                            users = [pscustomobject]@{ includeUsers = @(); includeGroups = @(); includeRoles = @() }
                        }
                        sessionControls = [pscustomobject]@{ globalSecureAccessFilteringProfile = [pscustomobject]@{ profileId = 'profile-id'; isEnabled = $true } }
                    })
                }
                default { return @() }
            }
        }
        Mock -ModuleName Gsa.Graph Invoke-MgGraphRequest {
            [pscustomobject]@{
                id = 'policy-id'; action = 'block'
                policyRules = @([pscustomobject]@{ ruleType = 'webCategory'; destinations = @([pscustomobject]@{ name = 'SocialNetworking' }) })
            }
        }

        $result = Test-GsaInternetBaseline -Name 'Baseline Filter' -BlockedCategories 'SocialNetworking' -SecurityProfileName 'Baseline Profile' -ConditionalAccessPolicyName 'Baseline CA'

        $result.FilteringPolicyId | Should -Be 'policy-id'
        $result.SecurityProfileId | Should -Be 'profile-id'
        $result.ConditionalAccessPolicyId | Should -Be 'ca-id'
        Assert-MockCalled -ModuleName Gsa.Graph Invoke-MgGraphRequest -ParameterFilter { $Method -eq 'POST' } -Times 0
    }
}
