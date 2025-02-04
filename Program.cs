﻿using Azure.Core;
using Azure.Identity;
using Microsoft.Azure.KeyVault.Models;
using Newtonsoft.Json;
using System.Net.Security;
using System.Web;
using System.Text;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Security.KeyVault.Secrets;

namespace managedIdentityClientTest
{

    /// <summary>
    /// Type representing the response of the SF Managed Identity endpoint for token acquisition requests.
    /// </summary>
    [JsonObject]
    public sealed class ManagedIdentityTokenResponse
    {
        [JsonProperty(Required = Required.Always, PropertyName = "token_type")]
        public string TokenType { get; set; }

        [JsonProperty(Required = Required.Always, PropertyName = "access_token")]
        public string AccessToken { get; set; }

        [JsonProperty(PropertyName = "expires_on")]
        public string ExpiresOn { get; set; }

        [JsonProperty(PropertyName = "resource")]
        public string Resource { get; set; }
    }

    /// <summary>
    /// Sample class demonstrating access token acquisition using Managed Identity.
    /// </summary>
    public sealed class AccessTokenAcquirer
    {
        private static ILogger log = new LoggerFactory().CreateLogger("AccessTokenAcquirer");
        private static Config config = new Config();
        private static HttpClient httpClient = new HttpClient();

        public static async Task Main(string[] args)
        {
            try
            {
                if (args.Length == 0)
                {
                    // see if config.json exists in the current directory
                    if (System.IO.File.Exists("config.json"))
                    {
                        string json = System.IO.File.ReadAllText("config.json");
                        config = JsonConvert.DeserializeObject<Config>(json);
                    }
                    await Run(config);
                    return;
                }
                if (args.Length == 1)
                {
                    // see if it is a path to a json file
                    if (System.IO.File.Exists(args[0]))
                    {
                        try
                        {
                            string json = System.IO.File.ReadAllText(args[0]);
                            config = JsonConvert.DeserializeObject<Config>(json);
                            await Run(config);
                            return;
                        }
                        catch (Exception ex)
                        {
                            Log($"Failed to parse json file: {ex.Message}");
                        }
                    }
                }
                else
                {
                    Log("Usage: managedIdentityClientTest [path to config.json]");
                    Log($"Example config:{JsonConvert.SerializeObject(config, Formatting.Indented)}");
                }
            }
            catch (Exception ex)
            {
                Log($"Exception: {ex.Message}");
            }
            finally
            {

            }
        }

        public static async Task Run(Config config)
        {
            AccessTokenAcquirer.config = config;
            Log("Acquiring access token...");
            //config.token = await AcquireAccessTokenAsync(config);
            switch (config.function)
            {
                case "mslearn":
                    config.token = await AcquireAccessTokenAsync(config);
                    break;
                case "current":
                    config.token = await AcquireCustomerAccessTokenAsync(config);
                    break;
                case "new":
                    config.token = await AcquireCustomerAccessTokenNewAsync(config);
                    break;
                default:
                    Log("No function specified [mslearn, current, new]. Running default function mslearn.");
                    config.token = await AcquireAccessTokenAsync(config);
                    break;
            }

            Log($"token: {config.token}");
            if (!string.IsNullOrEmpty(config.token))
            {
                Log("Token acquired. Probing secret...");
                var result = await ProbeSecretAsync(config);
                Log($"result: {result}");
            }
            else
            {
                Log("Failed to acquire token.");
            }
        }

        /// <summary>
        /// Acquire an access token.
        /// </summary>
        /// <returns>Access token</returns>
        public static async Task<string> AcquireAccessTokenAsync(Config config)
        {
            Log("AcquireAccessTokenAsync:Acquiring access token...");
            var managedIdentityEndpoint = config.endpoint;
            var managedIdentityAuthenticationCode = config.header;
            var managedIdentityServerThumbprint = config.thumbprint;
            // Latest api version, 2019-07-01-preview is still supported.
            var managedIdentityApiVersion = config.apiversion;
            var managedIdentityAuthenticationHeader = "secret";
            var resource = config.resourceId; //"https://management.azure.com/";
            var principalId = config.principalid;
            var requestUri = $"{managedIdentityEndpoint}?api-version={managedIdentityApiVersion}&resource={HttpUtility.UrlEncode(resource)}";

            if (!string.IsNullOrEmpty(principalId))
            {
                requestUri += $"&principalId={principalId}";
            }
            Log($"Requesting token from {requestUri}");
            var requestMessage = new HttpRequestMessage(HttpMethod.Get, requestUri);
            requestMessage.Headers.Add(managedIdentityAuthenticationHeader, managedIdentityAuthenticationCode);

            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, certChain, policyErrors) =>
            {
                // Do any additional validation here
                if (policyErrors == SslPolicyErrors.None)
                {
                    return true;
                }
                bool compare = 0 == string.Compare(cert.GetCertHashString(), managedIdentityServerThumbprint, StringComparison.OrdinalIgnoreCase);
                return compare;
            };

            try
            {
                var response = await new HttpClient(handler).SendAsync(requestMessage)
                    .ConfigureAwait(false);

                var tokenResponseString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                Log($"Token response: {tokenResponseString}");
                var tokenResponseObject = JsonConvert.DeserializeObject<ManagedIdentityTokenResponse>(tokenResponseString);
                Log(tokenResponseString);
                return tokenResponseObject.AccessToken;
            }
            catch (Exception ex)
            {
                string errorText = String.Format("{0} \n\n{1}", ex.Message, ex.InnerException != null ? ex.InnerException.Message : "Acquire token failed");
                Log(errorText);
            }

            return String.Empty;
        }

        public static async Task<string> AcquireCustomerAccessTokenAsync(Config config)
        {
            Log("AcquireCustomerAccessTokenAsync:Acquiring access token...");
            // https://learn.microsoft.com/en-us/aspnet/core/security/key-vault-configuration?view=aspnetcore-9.0
            var managedIdentityEndpoint = config.endpoint;
            var managedIdentityAuthenticationCode = config.header;
            var managedIdentityServerThumbprint = config.thumbprint;
            // Latest api version, 2019-07-01-preview is still supported.
            var managedIdentityApiVersion = config.apiversion;
            var managedIdentityAuthenticationHeader = "secret";
            var resource = config.resourceId; //"https://management.azure.com/";
            var principalId = config.principalid;
            var requestUri = $"{managedIdentityEndpoint}?api-version={managedIdentityApiVersion}&resource={HttpUtility.UrlEncode(resource)}";
            var secretUrl = new Uri(config.secretUrl);
            var secret = secretUrl.Segments[2].TrimEnd('/');
            var version = secretUrl.Segments[3].TrimEnd('/');
            var vault = $"{secretUrl.Scheme}://{secretUrl.Host}";

            if (!string.IsNullOrEmpty(principalId))
            {
                requestUri += $"&principalId={principalId}";
            }
            Log($"Requesting token from {requestUri}");
            // var requestMessage = new HttpRequestMessage(HttpMethod.Get, requestUri);
            // requestMessage.Headers.Add(managedIdentityAuthenticationHeader, managedIdentityAuthenticationCode);

            // var handler = new HttpClientHandler();
            // handler.ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, certChain, policyErrors) =>
            // {
            //     // Do any additional validation here
            //     if (policyErrors == SslPolicyErrors.None)
            //     {
            //         return true;
            //     }
            //     bool compare = 0 == string.Compare(cert.GetCertHashString(), managedIdentityServerThumbprint, StringComparison.OrdinalIgnoreCase);
            //     return compare;
            // };

            try
            {
                DateTimeOffset dto = DateTimeOffset.Now.AddMinutes(5);

                // var response = await new HttpClient(handler).SendAsync(requestMessage)
                //     .ConfigureAwait(false);

                // if (string.IsNullOrEmpty(config.token))
                // {
                //     var tokenResponseString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                //     Log($"Token response: {tokenResponseString}");
                //     ManagedIdentityTokenResponse? tokenResponseObject = JsonConvert.DeserializeObject<ManagedIdentityTokenResponse>(tokenResponseString);
                //     Log(tokenResponseString);
                //     // return tokenResponseObject.AccessToken;
                //     config.token = tokenResponseObject.AccessToken;
                //     dto = tokenResponseObject.ExpiresOn != null ? DateTimeOffset.FromUnixTimeSeconds(long.Parse(tokenResponseObject.ExpiresOn)) : dto;
                //     Log($"Token expires at: {dto.UtcDateTime}");
                // }

                TokenCredential tokenCredential = ConfigureAzureAccess(config);
                // AccessToken accessToken = new AccessToken(config.token, dto);
                // TokenCredential tokenCredential = DelegatedTokenCredential.Create((_, _) => accessToken);

                // var builder = WebApplication.CreateBuilder(args);
                WebApplicationBuilder? builder = WebApplication.CreateBuilder();

                Uri? uri = SetUpKeyVaultConfiguration(builder, tokenCredential, vault, (dto - DateTime.Now));
                string secretStr = GetSecret(config, tokenCredential);
                WebApplication app = StartWebApp(builder);
                return secretStr;

            }
            catch (Exception ex)
            {
                string errorText = String.Format("{0} \n\n{1}", ex.Message, ex.InnerException != null ? ex.InnerException.Message : "Acquire token failed");
                Log(errorText);
            }

            return String.Empty;
        }

        public static async Task<string> AcquireCustomerAccessTokenNewAsync(Config config)
        {
            Log("AcquireCustomerAccessTokenAsync:Acquiring access token...");
            // https://learn.microsoft.com/en-us/aspnet/core/security/key-vault-configuration?view=aspnetcore-9.0
            var managedIdentityEndpoint = config.endpoint;
            var managedIdentityAuthenticationCode = config.header;
            var managedIdentityServerThumbprint = config.thumbprint;
            // Latest api version, 2019-07-01-preview is still supported.
            var managedIdentityApiVersion = config.apiversion;
            var managedIdentityAuthenticationHeader = "secret";
            var resource = config.resourceId; //"https://management.azure.com/";
            var principalId = config.principalid;
            var requestUri = $"{managedIdentityEndpoint}?api-version={managedIdentityApiVersion}&resource={HttpUtility.UrlEncode(resource)}";
            var secretUrl = new Uri(config.secretUrl);
            var secret = secretUrl.Segments[2].TrimEnd('/');
            var version = secretUrl.Segments[3].TrimEnd('/');
            var vault = $"{secretUrl.Scheme}://{secretUrl.Host}";

            if (!string.IsNullOrEmpty(principalId))
            {
                requestUri += $"&principalId={principalId}";
            }
            Log($"Requesting token from {requestUri}");
            var requestMessage = new HttpRequestMessage(HttpMethod.Get, requestUri);
            requestMessage.Headers.Add(managedIdentityAuthenticationHeader, managedIdentityAuthenticationCode);

            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, certChain, policyErrors) =>
            {
                // Do any additional validation here
                if (policyErrors == SslPolicyErrors.None)
                {
                    return true;
                }
                bool compare = 0 == string.Compare(cert.GetCertHashString(), managedIdentityServerThumbprint, StringComparison.OrdinalIgnoreCase);
                return compare;
            };

            try
            {
                DateTimeOffset dto = DateTimeOffset.Now.AddMinutes(5);

                var response = await new HttpClient(handler).SendAsync(requestMessage)
                    .ConfigureAwait(false);

                if (string.IsNullOrEmpty(config.token))
                {
                    var tokenResponseString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    Log($"Token response: {tokenResponseString}");
                    ManagedIdentityTokenResponse? tokenResponseObject = JsonConvert.DeserializeObject<ManagedIdentityTokenResponse>(tokenResponseString);
                    Log(tokenResponseString);
                    // return tokenResponseObject.AccessToken;
                    config.token = tokenResponseObject.AccessToken;
                    dto = tokenResponseObject.ExpiresOn != null ? DateTimeOffset.FromUnixTimeSeconds(long.Parse(tokenResponseObject.ExpiresOn)) : dto;
                    Log($"Token expires at: {dto.UtcDateTime}");
                }

                // TokenCredential tokenCredential = ConfigureAzureAccess(config);
                AccessToken accessToken = new AccessToken(config.token, dto);
                TokenCredential tokenCredential = DelegatedTokenCredential.Create((_, _) => accessToken);

                // var builder = WebApplication.CreateBuilder(args);
                var builder = WebApplication.CreateBuilder();

                Uri? uri = SetUpKeyVaultConfiguration(builder, tokenCredential, vault, (dto - DateTime.Now));
                StartWebApp(builder);
                string secretStr = GetSecret(config, tokenCredential);
                return secretStr;
            }
            catch (Exception ex)
            {
                string errorText = String.Format("{0} \n\n{1}", ex.Message, ex.InnerException != null ? ex.InnerException.Message : "Acquire token failed");
                Log(errorText);
            }

            return String.Empty;
        }

        public static string GetSecret(Config config, TokenCredential tokenCredential)
        {
            var secretUrl = new Uri(config.secretUrl);
            var secret = secretUrl.Segments[2].TrimEnd('/');
            var version = secretUrl.Segments[3].TrimEnd('/');
            var vault = $"{secretUrl.Scheme}://{secretUrl.Host}";

            Log("GetSecret:Retrieving secret...");
            SecretClientOptions options = new SecretClientOptions()
            {
                Retry =
                {
                    Delay= TimeSpan.FromSeconds(2),
                    MaxDelay = TimeSpan.FromSeconds(16),
                    MaxRetries = 5,
                    Mode = RetryMode.Exponential
                }
            };
            var client = new SecretClient(new Uri(vault), tokenCredential, options);

            KeyVaultSecret secretObj = client.GetSecret(secret);

            string secretValue = secretObj.Value;
            Log($"GetSecret:Secret: {secretValue}");
            return secretValue;
        }

        public static WebApplication StartWebApp(WebApplicationBuilder builder)
        {
            //https://github.com/dotnet/AspNetCore.Docs/blob/main/aspnetcore/security/key-vault-configuration/samples/6.x/KeyVaultConfigurationSample/Program.cs
            Log("BuildWebHost:Building web host...");
            Log("Building app...");
            WebApplication? app = builder.Build();
            app.MapGet("/", () => "Hello World!");
            // Task.Run(() => app.Run());
            app.Start();
            Log($"app urls: {JsonConvert.SerializeObject(app.Urls)}");
            return app;
        }

        public static Uri? SetUpKeyVaultConfiguration(WebApplicationBuilder builder, TokenCredential tokenCredential, string keyVaultUri, TimeSpan? reloadInterval = null)
        {
            //https://learn.microsoft.com/en-us/dotnet/api/microsoft.extensions.configuration.azurekeyvaultconfigurationextensions.addazurekeyvault?view=azure-dotnet#microsoft-extensions-configuration-azurekeyvaultconfigurationextensions-addazurekeyvault(microsoft-extensions-configuration-iconfigurationbuilder-system-uri-azure-core-tokencredential)
            Log("SetUpKeyVaultConfiguration:Setting up KeyVault configuration...");
            builder.Configuration.AddAzureKeyVault(
                // new Uri($"https://{builder.Configuration["KeyVaultName"]}.vault.azure.net/"),
                new Uri(keyVaultUri),
                tokenCredential,
                    new AzureKeyVaultConfigurationOptions
                    {
                        Manager = new KeyVaultSecretManager(),
                        ReloadInterval = reloadInterval ?? TimeSpan.FromMinutes(1)
                    });
            return new Uri(keyVaultUri);
        }

        public static TokenCredential ConfigureAzureAccess(Config config)
        {
            Log("ConfigureAzureAccess:Configuring Azure access...");
            if (string.IsNullOrEmpty(config.principalid))
            {
                Log("ConfigureAzureAccess:Using default Managed Identity Credential");
                return new ManagedIdentityCredential();
            }
            Log($"ConfigureAzureAccess:Using Managed Identity Credential with principalid: {config.principalid}");
            return new ManagedIdentityCredential(config.principalid);
        }

        public static async Task<string> ProbeSecretAsync(Config config)
        {
            Log("ProbeSecretAsync:Probing secret...");
            // initialize a KeyVault client with a managed identity-based authentication callback
            // convert the secretUrl from Uri to vault and secret name
            var secretUrl = new Uri(config.secretUrl);
            var secret = secretUrl.Segments[2].TrimEnd('/');
            var version = secretUrl.Segments[3].TrimEnd('/');
            var vault = $"{secretUrl.Scheme}://{secretUrl.Host}";
            var endpoint = config.endpoint;
            var token = config.token;
            var header = config.header;
            var kvClient = new Microsoft.Azure.KeyVault.KeyVaultClient(new Microsoft.Azure.KeyVault.KeyVaultClient.AuthenticationCallback((a, r, s) => { return AuthenticationCallbackAsync(a, r, s); }));

            Log($"\nRunning with configuration: \n\tobserved vault: {vault}\n\tobserved secret: {secret}\n\tMI endpoint: {endpoint}\n\tMI auth code: {token}\n\tMI auth header: {header}");
            string response = String.Empty;

            Log("\n== {DateTime.UtcNow.ToString()}: Probing secret...");
            try
            {
                var secretResponse = await kvClient.GetSecretWithHttpMessagesAsync(vault, secret, version).ConfigureAwait(false);

                if (secretResponse.Response.IsSuccessStatusCode)
                {
                    // use the secret: secretValue.Body.Value;
                    response = String.Format($"Successfully probed secret '{secret}' in vault '{vault}': {PrintSecretBundleMetadata(secretResponse.Body)}");
                }
                else
                {
                    response = String.Format($"Non-critical error encountered retrieving secret '{secret}' in vault '{vault}': {secretResponse.Response.ReasonPhrase} ({secretResponse.Response.StatusCode})");
                }
            }
            catch (Microsoft.Rest.ValidationException ve)
            {
                response = String.Format($"encountered REST validation exception 0x{ve.HResult.ToString("X")} trying to access '{secret}' in vault '{vault}' from {ve.Source}: {ve.Message}");
                Log(ve.ToString());
            }
            catch (KeyVaultErrorException kvee)
            {
                response = String.Format($"encountered KeyVault exception 0x{kvee.HResult.ToString("X")} trying to access '{secret}' in vault '{vault}': {kvee.Response.ReasonPhrase} ({kvee.Response.StatusCode})");
                Log(kvee.ToString());
            }
            catch (Exception ex)
            {
                // handle generic errors here
                response = String.Format($"encountered exception 0x{ex.HResult.ToString("X")} trying to access '{secret}' in vault '{vault}': {ex.Message}");
                // convert exception to string using ToString() for logging including stack trace and inner exceptions
                Log(ex.ToString());
            }

            Log(response);

            return response;
        }

        private static string PrintSecretBundleMetadata(SecretBundle bundle)
        {
            Log("PrintSecretBundleMetadata:Printing secret bundle metadata...");
            StringBuilder strBuilder = new StringBuilder();

            strBuilder.AppendFormat($"\n\tid: {bundle.Id}\n");
            strBuilder.AppendFormat($"\tcontent type: {bundle.ContentType}\n");
            strBuilder.AppendFormat($"\tmanaged: {bundle.Managed}\n");
            strBuilder.AppendFormat($"\tattributes:\n");
            strBuilder.AppendFormat($"\t\tenabled: {bundle.Attributes.Enabled}\n");
            strBuilder.AppendFormat($"\t\tnbf: {bundle.Attributes.NotBefore}\n");
            strBuilder.AppendFormat($"\t\texp: {bundle.Attributes.Expires}\n");
            strBuilder.AppendFormat($"\t\tcreated: {bundle.Attributes.Created}\n");
            strBuilder.AppendFormat($"\t\tupdated: {bundle.Attributes.Updated}\n");
            strBuilder.AppendFormat($"\t\trecoveryLevel: {bundle.Attributes.RecoveryLevel}\n");

            return strBuilder.ToString();
        }

        /// <summary>
        /// KV authentication callback, using the application's managed identity.
        /// </summary>
        /// <param name="authority">The expected issuer of the access token, from the KV authorization challenge.</param>
        /// <param name="resource">The expected audience of the access token, from the KV authorization challenge.</param>
        /// <param name="scope">The expected scope of the access token; not currently used.</param>
        /// <returns>Access token</returns>
        public static async Task<string> AuthenticationCallbackAsync(string authority, string resource, string scope)
        {
            Log("AuthenticationCallbackAsync:Authentication callback invoked...");
            Log($"authentication callback invoked with: auth: {authority}, resource: {resource}, scope: {scope}");
            var encodedResource = HttpUtility.UrlEncode(resource);

            var requestUri = $"{config.endpoint}?api-version={config.apiversion}&resource={encodedResource}";
            Log($"request uri: {requestUri}");

            var requestMessage = new HttpRequestMessage(HttpMethod.Get, requestUri);
            requestMessage.Headers.Add("secret", $"{config.header}");
            Log($"added header 'secret':'{config.header}'");

            try
            {
                var customHandler = new HttpClientHandler();
                customHandler.ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, certChain, policyErrors) =>
                {
                    // Do any additional validation here
                    if (policyErrors == SslPolicyErrors.None)
                    {
                        return true;
                    }
                    bool compare = 0 == string.Compare(cert.GetCertHashString(), config.thumbprint, StringComparison.OrdinalIgnoreCase);
                    return compare;
                };
                var client = new HttpClient(customHandler);
                var response = await client.SendAsync(requestMessage).ConfigureAwait(false);
                Log($"response status: success: {response.IsSuccessStatusCode}, status: {response.StatusCode}");

                response.EnsureSuccessStatusCode();

                var tokenResponseString = await response.Content.ReadAsStringAsync()
                    .ConfigureAwait(false);

                var tokenResponse = JsonConvert.DeserializeObject<ManagedIdentityTokenResponse>(tokenResponseString);
                Log("deserialized token response; returning access code..");

                return tokenResponse.AccessToken;
            }
            catch (HttpRequestException hre)
            {
                Log($"HTTP request exception in authentication callback: {hre.Message}");
                Log($"exception details: {hre.ToString()}");
                throw;
            }
            catch (Exception ex)
            {
                Log($"exception in authentication callback: {ex.Message}");
                Log($"exception details: {ex.ToString()}");
                throw;
            }
        }

        private enum LogLevel
        {
            Info,
            Verbose
        };

        private static void Log(string message = "", LogLevel level = LogLevel.Info)
        {
            Console.WriteLine($"[{DateTime.Now}][{level}]: {message}");
        }
    } // class AccessTokenAcquirer

    public class Config
    {
        //<endpoint> <header> <thumbprint> <vault> <secret> <version> [apiVersion]
        public string endpoint { get; set; }
        public string header { get; set; }
        public string thumbprint { get; set; }
        public string principalid { get; set; }
        public string resourceId { get; set; }
        public string secretUrl { get; set; }
        public string apiversion { get; set; }
        public string token { get; set; }
        public string function { get; set; }
    }
}