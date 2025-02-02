using Azure.Core;
using Azure.Identity;
using Microsoft.Azure.KeyVault.Models;
using Newtonsoft.Json;
using System.Net.Security;
using System.Web;
using System.Text;

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
        }

        public static async Task Run(Config config)
        {
            AccessTokenAcquirer.config = config;
            Log("Acquiring access token...");
            //config.token = await AcquireAccessTokenAsync(config);
            config.token = await AcquireCustomerAccessTokenAsync(config);
            var result = await ProbeSecretAsync(config);
            Log($"token: {config.token}");
            Log($"result: {result}");
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

                TokenCredential tokenCredential = ConfigureAzureAccess(config);
                // var builder = WebApplication.CreateBuilder(args);
                var builder = WebApplication.CreateBuilder();

                Uri? uri = SetUpKeyVaultConfiguration(builder, tokenCredential, vault, new TimeSpan(0, 0, 30, 0));
                return uri.ToString();

                // var response = await new HttpClient(handler).SendAsync(requestMessage)
                //     .ConfigureAwait(false);

                // var tokenResponseString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                // Log($"Token response: {tokenResponseString}");
                // var tokenResponseObject = JsonConvert.DeserializeObject<ManagedIdentityTokenResponse>(tokenResponseString);
                // Log(tokenResponseString);
                // return tokenResponseObject.AccessToken;
            }
            catch (Exception ex)
            {
                string errorText = String.Format("{0} \n\n{1}", ex.Message, ex.InnerException != null ? ex.InnerException.Message : "Acquire token failed");
                Log(errorText);
            }

            return String.Empty;
        }

        public static Uri? SetUpKeyVaultConfiguration(WebApplicationBuilder builder, TokenCredential tokenCredential, string keyVaultUri, TimeSpan? cacheDuration = null)
        {
            Log("SetUpKeyVaultConfiguration:Setting up KeyVault configuration...");
            builder.Configuration.AddAzureKeyVault(
                // new Uri($"https://{builder.Configuration["KeyVaultName"]}.vault.azure.net/"),
                new Uri(keyVaultUri),
                tokenCredential);
                    // new ClientCertificateCredential(
                    //     builder.Configuration["AzureADDirectoryId"],
                    //     builder.Configuration["AzureADApplicationId"],
                    //     x509Certificate));
                    // }
            return null;
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
    }
}