@description('Key Vault name.')
param name string

@description('Azure region.')
param location string

@description('Deployment principal object ID.')
param principalId string

@allowed([
  'User'
  'ServicePrincipal'
  'Group'
])
param principalType string

@allowed([
  'Enabled'
  'Disabled'
])
param publicNetworkAccess string = 'Enabled'

param tags object = {}

var certificatesOfficerRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'a4417e6f-fecd-4de8-b567-7b0420556985'
)
var cryptoUserRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '12338af0-0e69-4776-bea7-57ae8d297424'
)

resource vault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'premium'
    }
    accessPolicies: []
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    publicNetworkAccess: publicNetworkAccess
    networkAcls: {
      bypass: 'None'
      defaultAction: publicNetworkAccess == 'Disabled' ? 'Deny' : 'Allow'
    }
  }
}

resource certificatesOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, principalId, certificatesOfficerRoleId)
  scope: vault
  properties: {
    roleDefinitionId: certificatesOfficerRoleId
    principalId: principalId
    principalType: principalType
    description: 'Manage the GSA root CA certificate lifecycle.'
  }
}

resource cryptoUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, principalId, cryptoUserRoleId)
  scope: vault
  properties: {
    roleDefinitionId: cryptoUserRoleId
    principalId: principalId
    principalType: principalType
    description: 'Sign GSA certificates and CRLs with the non-exportable HSM key.'
  }
}

output name string = vault.name
output uri string = vault.properties.vaultUri
output id string = vault.id
