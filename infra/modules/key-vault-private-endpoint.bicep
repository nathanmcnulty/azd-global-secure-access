param location string
param keyVaultName string
param subnetResourceId string
param privateDnsZoneResourceId string
param tags object = {}

resource vault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: keyVaultName
}

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2024-07-01' = {
  name: 'pe-${keyVaultName}'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: subnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'vault'
        properties: {
          privateLinkServiceId: vault.id
          groupIds: [
            'vault'
          ]
          requestMessage: 'GSA certificate signing and CRL renewal'
        }
      }
    ]
  }
}
resource dnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-07-01' = {
  parent: privateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'vault'
        properties: {
          privateDnsZoneId: privateDnsZoneResourceId
        }
      }
    ]
  }
}
