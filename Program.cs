using System.Net.Security;
using System.Text;
using System.Web;
using Newtonsoft.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.KeyVault.Models;
using System.Text.RegularExpressions;

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

        public static void Main(string[] args)
        {
            if(args.Length == 0)
            {
                // see if config.json exists in the current directory
                if (System.IO.File.Exists("config.json"))
                {
                    string json = System.IO.File.ReadAllText("config.json");
                    config = JsonConvert.DeserializeObject<Config>(json);
                }
                Run(config);
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
                        Run(config);
                        return;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to parse json file: {ex.Message}");
                    }
                }
                // see if it is json string that can be deserialized into Config
                try
                {
                    config = JsonConvert.DeserializeObject<Config>(args[0]);
                    Run(config);
                    return;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to parse json string: {ex.Message}");
                }
            }
        }

        public static void Run(Config config)
        {
            // AccessTokenAcquirer.config = config;
            //# '2020-05-01' # 2448 has 2024-06-11
            Console.WriteLine($"Acquiring access token using Managed Identity");

            var token = AcquireAccessTokenAsync(config).Result;
            config.token = token;
            var result = ProbeSecretAsync(config).Result;
            Console.WriteLine(token);
        }

        /// <summary>
        /// Acquire an access token.
        /// </summary>
        /// <returns>Access token</returns>
        public static async Task<string> AcquireAccessTokenAsync(Config config)
        {
            var managedIdentityEndpoint = config.endpoint;
            var managedIdentityAuthenticationCode = config.header;
            var managedIdentityServerThumbprint = config.thumbprint;
            // Latest api version, 2019-07-01-preview is still supported.
            var managedIdentityApiVersion = config.apiversion;
            var managedIdentityAuthenticationHeader = "secret";
            var resource = config.resourceId; //"https://management.azure.com/";

            var requestUri = $"{managedIdentityEndpoint}?api-version={managedIdentityApiVersion}&resource={HttpUtility.UrlEncode(resource)}";

            Console.WriteLine($"Requesting token from {requestUri}");
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

                response.EnsureSuccessStatusCode();
                var tokenResponseString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var tokenResponseObject = JsonConvert.DeserializeObject<ManagedIdentityTokenResponse>(tokenResponseString);

                return tokenResponseObject.AccessToken;
            }
            catch (Exception ex)
            {
                string errorText = String.Format("{0} \n\n{1}", ex.Message, ex.InnerException != null ? ex.InnerException.Message : "Acquire token failed");
                Console.WriteLine(errorText);
            }

            return String.Empty;
        }

        public static async Task<string> ProbeSecretAsync(Config config)
        {
            // initialize a KeyVault client with a managed identity-based authentication callback
            var kvClient = new Microsoft.Azure.KeyVault.KeyVaultClient(new Microsoft.Azure.KeyVault.KeyVaultClient.AuthenticationCallback((a, r, s) => { return AuthenticationCallbackAsync(a, r, s); }));
            // convert the secretUrl from Uri to vault and secret name
            var secretUrl = new Uri(config.secretUrl);
            var secret = secretUrl.Segments[2].TrimEnd('/');
            var version = secretUrl.Segments[3].TrimEnd('/');
            var vault = $"{secretUrl.Scheme}://{secretUrl.Host}";
            var endpoint = config.endpoint;
            var token = config.token;
            var header = config.header;
            
            Log(LogLevel.Info, $"\nRunning with configuration: \n\tobserved vault: {vault}\n\tobserved secret: {secret}\n\tMI endpoint: {endpoint}\n\tMI auth code: {token}\n\tMI auth header: {header}");
            string response = String.Empty;

            Log(LogLevel.Info, "\n== {DateTime.UtcNow.ToString()}: Probing secret...");
            try
            {
                var secretResponse = await kvClient.GetSecretWithHttpMessagesAsync(vault, secret, version)
                    .ConfigureAwait(false);

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
            }
            catch (KeyVaultErrorException kvee)
            {
                response = String.Format($"encountered KeyVault exception 0x{kvee.HResult.ToString("X")} trying to access '{secret}' in vault '{vault}': {kvee.Response.ReasonPhrase} ({kvee.Response.StatusCode})");
            }
            catch (Exception ex)
            {
                // handle generic errors here
                response = String.Format($"encountered exception 0x{ex.HResult.ToString("X")} trying to access '{secret}' in vault '{vault}': {ex.Message}");
            }

            Log(LogLevel.Info, response);

            return response;
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
            Log(LogLevel.Verbose, $"authentication callback invoked with: auth: {authority}, resource: {resource}, scope: {scope}");
            var encodedResource = HttpUtility.UrlEncode(resource);

            // This sample does not illustrate the caching of the access token, which the user application is expected to do.
            // For a given service, the caching key should be the (encoded) resource uri. The token should be cached for a period
            // of time at most equal to its remaining validity. The 'expires_on' field of the token response object represents
            // the number of seconds from Unix time when the token will expire. You may cache the token if it will be valid for at
            // least another short interval (1-10s). If its expiration will occur shortly, don't cache but still return it to the 
            // caller. The MI endpoint will not return an expired token.
            // Sample caching code:
            //
            // ManagedIdentityTokenResponse tokenResponse;
            // if (responseCache.TryGetCachedItem(encodedResource, out tokenResponse))
            // {
            //     Log(LogLevel.Verbose, $"cache hit for key '{encodedResource}'");
            //
            //     return tokenResponse.AccessToken;
            // }
            //
            // Log(LogLevel.Verbose, $"cache miss for key '{encodedResource}'");
            //
            // where the response cache is left as an exercise for the reader. MemoryCache is a good option, albeit not yet available on .net core.

            var requestUri = $"{config.endpoint}?api-version={config.apiversion}&resource={encodedResource}";
            Log(LogLevel.Verbose, $"request uri: {requestUri}");

            var requestMessage = new HttpRequestMessage(HttpMethod.Get, requestUri);
            requestMessage.Headers.Add(config.header, config.token);
            Log(LogLevel.Verbose, $"added header '{config.header}': '{config.token}'");

            var response = await httpClient.SendAsync(requestMessage)
                .ConfigureAwait(false);
            Log(LogLevel.Verbose, $"response status: success: {response.IsSuccessStatusCode}, status: {response.StatusCode}");

            response.EnsureSuccessStatusCode();

            var tokenResponseString = await response.Content.ReadAsStringAsync()
                .ConfigureAwait(false);

            var tokenResponse = JsonConvert.DeserializeObject<ManagedIdentityTokenResponse>(tokenResponseString);
            Log(LogLevel.Verbose, "deserialized token response; returning access code..");

            // Sample caching code (continuation):
            // var expiration = DateTimeOffset.FromUnixTimeSeconds(Int32.Parse(tokenResponse.ExpiresOn));
            // if (expiration > DateTimeOffset.UtcNow.AddSeconds(5.0))
            //    responseCache.AddOrUpdate(encodedResource, tokenResponse, expiration);

            return tokenResponse.AccessToken;
        }

        private static string PrintSecretBundleMetadata(SecretBundle bundle)
        {
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

        private enum LogLevel
        {
            Info,
            Verbose
        };

        private static void Log(LogLevel level, string message)
        {
            if (level != LogLevel.Verbose)
            {
                Console.WriteLine(message);
            }
        }
    } // class AccessTokenAcquirer

    public class Config
    {
        //<endpoint> <header> <thumbprint> <vault> <secret> <version> [apiVersion]
        public string endpoint { get; set; }
        public string header { get; set; }
        public string thumbprint { get; set; }
        public string clientId { get; set; }
        public string resourceId { get; set; }
        public string secretUrl { get; set; }
        public string apiversion { get; set; }
        public string token { get; set; }
    }
}