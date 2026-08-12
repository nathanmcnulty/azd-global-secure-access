@description('Globally unique storage account name.')
param name string

param location string
param principalId string

@allowed([
  'User'
  'ServicePrincipal'
  'Group'
])
param principalType string

param tags object = {}

var blobDataOwnerRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
)
var storageAccountContributorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '17d1049b-9a84-46fb-8f53-869881c3d3ab'
)

resource storage 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: name
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: false
    accessTier: 'Hot'
    allowCrossTenantReplication: false
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 30
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 30
    }
  }
}

resource dataOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, principalId, blobDataOwnerRoleId)
  scope: storage
  properties: {
    roleDefinitionId: blobDataOwnerRoleId
    principalId: principalId
    principalType: principalType
    description: 'Publish and verify signed CRLs using Microsoft Entra authorization.'
  }
}

resource serviceContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, principalId, storageAccountContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: storageAccountContributorRoleId
    principalId: principalId
    principalType: principalType
    description: 'Enable and inspect the static website endpoint without using a Storage Shared Key.'
  }
}

output name string = storage.name
output id string = storage.id
output webEndpoint string = storage.properties.primaryEndpoints.web
