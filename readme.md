# to test service fabric managed identity token service with key vault

## prepare cluster

1. create a service fabric cluster with managed identity token service enabled
1. create a service fabric application with a service that uses the managed identity token service
1. create a service principal with the necessary permissions to access key vault
    secret get, list
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

### example applicationManifest.xml with managedIdentity and principalId

```xml
<?xml version="1.0" encoding="utf-8"?>
<ApplicationManifest xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ApplicationTypeName="VotingType" ApplicationTypeVersion="1.0.2" xmlns="http://schemas.microsoft.com/2011/01/fabric">
  <Parameters>
    <Parameter Name="VotingData_MinReplicaSetSize" DefaultValue="3" />
    <Parameter Name="VotingData_PartitionCount" DefaultValue="1" />
    <Parameter Name="VotingData_TargetReplicaSetSize" DefaultValue="3" />
    <Parameter Name="VotingWeb_InstanceCount" DefaultValue="-1" />
  </Parameters>
\  <ServiceManifestImport>
    <ServiceManifestRef ServiceManifestName="VotingDataPkg" ServiceManifestVersion="1.0.2" />
    <ConfigOverrides />
  </ServiceManifestImport>
  <ServiceManifestImport>
    <ServiceManifestRef ServiceManifestName="VotingWebPkg" ServiceManifestVersion="1.0.2" />
    <ConfigOverrides />
    <Policies>
      <IdentityBindingPolicy ServiceIdentityRef="WebAdmin" ApplicationIdentityRef="AdminUser" />
    </Policies>
  </ServiceManifestImport>
  <DefaultServices>
    <Service Name="VotingData">
      <StatefulService ServiceTypeName="VotingDataType" TargetReplicaSetSize="[VotingData_TargetReplicaSetSize]" MinReplicaSetSize="[VotingData_MinReplicaSetSize]">
        <UniformInt64Partition PartitionCount="[VotingData_PartitionCount]" LowKey="0" HighKey="25" />
      </StatefulService>
    </Service>
    <Service Name="VotingWeb" ServicePackageActivationMode="ExclusiveProcess">
      <StatelessService ServiceTypeName="VotingWebType" InstanceCount="[VotingWeb_InstanceCount]">
        <SingletonPartition />
      </StatelessService>
    </Service>
  </DefaultServices>
  <Principals>
    <Users>
      <User Name="SetupLocalSystem">
        <MemberOf>
          <SystemGroup Name="Administrators" />
        </MemberOf>
      </User>
    </Users>
    <ManagedIdentities>
      <!-- add PrincipalId (objectid) attribute here -->
      <ManagedIdentity Name="AdminUser" PrincipalId="ac78a5b3-9c8e-42a9-befe-8ba1b52ec286" />
    </ManagedIdentities>
  </Principals>
</ApplicationManifest>
```

### reference

https://learn.microsoft.com/en-us/azure/service-fabric/how-to-deploy-service-fabric-application-user-assigned-managed-identity

https://learn.microsoft.com/en-us/azure/service-fabric/concepts-managed-identity

https://learn.microsoft.com/en-us/aspnet/core/security/key-vault-configuration?view=aspnetcore-9.0

https://learn.microsoft.com/en-us/azure/service-fabric/how-to-managed-identity-service-fabric-app-code

https://github.com/dotnet/AspNetCore.Docs/blob/main/aspnetcore/security/key-vault-configuration/samples/6.x/KeyVaultConfigurationSample/Program.cs

https://learn.microsoft.com/en-us/dotnet/api/microsoft.extensions.configuration.azurekeyvaultconfigurationextensions.addazurekeyvault?view=azure-dotnet#microsoft-extensions-configuration-azurekeyvaultconfigurationextensions-addazurekeyvault(microsoft-extensions-configuration-iconfigurationbuilder-system-uri-azure-core-tokencredential)
