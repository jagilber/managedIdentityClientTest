# to test service fabric managed identity token service with key vault

## prepare cluster

1. create a service fabric cluster with managed identity token service enabled
1. create a service fabric application with a service that uses the managed identity token service
1. create a service principal with the necessary permissions to access the managed identity token service
1. deploy the application to the cluster via ARM template
1. rdp into node and run process explorer to view environment variables of published application / service

## test

1. on node extract the publish.zip file
  .net 6 core app
1. create/modify the config.json in working directory to include the identity environment variables from above
1. test with and without the principalid
    this attribute can be specified in appmanifest for custom user assigned managed identity per app
1. for 'function' use 
    'mslearn' for modified mslearn documentation version working with all sf versions, 
        https://learn.microsoft.com/en-us/azure/service-fabric/how-to-managed-identity-service-fabric-app-code
    'new' AddAzureKeyVault / GetSecret with Delegated prefeteched MITS token for new version working with sf > 10.1.2338,
    'current' AddAzureKeyVault / GetSecret with defined ManagedIdentityCredential for current version not working with sf > 10.1.2338
1. run the application
    ```cmd
    .\managedIdentityClientTest.exe
    ```

### example config.json

```json
{
  "endpoint": "https://10.0.0.4:2377/metadata/identity/oauth2/token",
  "header": "eyAidHlwIiA6ICJ...",
  "thumbprint": "",
  "principalid": "", 
  "resourceid": "https://vault.azure.net",
  "secreturl": "",
  "apiversion": "2024-06-11",
  "token": null,
  "function": "" // current, mslearn, new
}
```

### reference

https://learn.microsoft.com/en-us/azure/service-fabric/concepts-managed-identity

https://learn.microsoft.com/en-us/aspnet/core/security/key-vault-configuration?view=aspnetcore-9.0

https://github.com/dotnet/AspNetCore.Docs/blob/main/aspnetcore/security/key-vault-configuration/samples/6.x/KeyVaultConfigurationSample/Program.cs

https://learn.microsoft.com/en-us/dotnet/api/microsoft.extensions.configuration.azurekeyvaultconfigurationextensions.addazurekeyvault?view=azure-dotnet#microsoft-extensions-configuration-azurekeyvaultconfigurationextensions-addazurekeyvault(microsoft-extensions-configuration-iconfigurationbuilder-system-uri-azure-core-tokencredential)
