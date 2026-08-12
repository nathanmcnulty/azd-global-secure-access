targetScope = 'subscription'

@description('Azure region for resource deployment.')
param location string

@minLength(1)
@description('Short organization or lab identifier used in resource names and certificate subjects.')
param organizationName string

@description('Name of the resource group created for the proof of concept.')
param resourceGroupName string

@description('Object ID of the user or service principal running azd.')
param principalId string

@allowed([
  'User'
  'ServicePrincipal'
  'Group'
])
@description('Microsoft Entra object type represented by principalId.')
param principalType string = 'User'

@description('Optional resource tags.')
param tags object = {}

@description('Enable Key Vault diagnostic settings. Requires logAnalyticsWorkspaceResourceId.')
param enableDiagnostics bool = false

@description('Existing Log Analytics workspace resource ID for diagnostics.')
param logAnalyticsWorkspaceResourceId string = ''

@description('Enable Microsoft Defender for Key Vault at subscription scope. This changes subscription billing.')
param enableDefenderForKeyVault bool = false

@description('Create a Key Vault private endpoint. The azd runner must have private DNS and network reachability.')
param enablePrivateEndpoint bool = false

@description('Existing subnet resource ID for the Key Vault private endpoint.')
param privateEndpointSubnetResourceId string = ''

@description('Existing privatelink.vaultcore.azure.net private DNS zone resource ID.')
param privateDnsZoneResourceId string = ''

@description('Private endpoint region. Defaults to location; set this to the existing subnet/VNet region when different.')
param privateEndpointLocation string = ''

var resourceToken = uniqueString(subscription().id, resourceGroupName, organizationName)
var keyVaultName = 'kvgsa${resourceToken}'
var storageAccountName = 'gsacrl${resourceToken}'
var baseTags = union({
  'azd-env-name': resourceGroupName
  purpose: 'Microsoft Entra Global Secure Access proof of concept'
  managedBy: 'azd'
}, tags)

resource resourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: resourceGroupName
  location: location
  tags: baseTags
}

module keyVault 'modules/key-vault.bicep' = {
  name: 'key-vault'
  scope: resourceGroup
  params: {
    location: location
    name: keyVaultName
    principalId: principalId
    principalType: principalType
    publicNetworkAccess: enablePrivateEndpoint ? 'Disabled' : 'Enabled'
    tags: baseTags
  }
}

module crlStorage 'modules/crl-storage.bicep' = {
  name: 'crl-storage'
  scope: resourceGroup
  params: {
    location: location
    name: storageAccountName
    principalId: principalId
    principalType: principalType
    tags: baseTags
  }
}

module diagnostics 'modules/diagnostics.bicep' = if (enableDiagnostics) {
  name: 'diagnostics'
  scope: resourceGroup
  params: {
    keyVaultName: keyVaultName
    workspaceResourceId: logAnalyticsWorkspaceResourceId
  }
  dependsOn: [
    keyVault
  ]
}

module privateEndpoint 'modules/key-vault-private-endpoint.bicep' = if (enablePrivateEndpoint) {
  name: 'key-vault-private-endpoint'
  scope: resourceGroup
  params: {
    location: empty(privateEndpointLocation) ? location : privateEndpointLocation
    keyVaultName: keyVaultName
    subnetResourceId: privateEndpointSubnetResourceId
    privateDnsZoneResourceId: privateDnsZoneResourceId
    tags: baseTags
  }
  dependsOn: [
    keyVault
  ]
}

module defender 'modules/defender-for-key-vault.bicep' = if (enableDefenderForKeyVault) {
  name: 'defender-for-key-vault'
  scope: subscription()
}

output AZURE_RESOURCE_GROUP string = resourceGroup.name
output AZURE_LOCATION string = location
output AZURE_PRINCIPAL_ID string = principalId
output GSA_KEY_VAULT_NAME string = keyVault.outputs.name
output GSA_KEY_VAULT_URI string = keyVault.outputs.uri
output GSA_CRL_STORAGE_ACCOUNT_NAME string = crlStorage.outputs.name
output GSA_CRL_WEB_ENDPOINT string = crlStorage.outputs.webEndpoint
output GSA_PRIVATE_ENDPOINT_ENABLED bool = enablePrivateEndpoint
