using System.Web;
using Newtonsoft.Json;
using Microsoft.Extensions.Logging;

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
            config.token = await AcquireAccessTokenAsync(config);
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
            var managedIdentityEndpoint = config.endpoint;
            var managedIdentityAuthenticationCode = config.header;
            var managedIdentityServerThumbprint = config.thumbprint;
            // Latest api version, 2019-07-01-preview is still supported.
            var managedIdentityApiVersion = config.apiversion;
            var managedIdentityAuthenticationHeader = "secret";
            var resource = config.resourceId; //"https://management.azure.com/";
            var principalId = config.principalId;
            var requestUri = $"{managedIdentityEndpoint}?api-version={managedIdentityApiVersion}&resource={HttpUtility.UrlEncode(resource)}";

            if (!string.IsNullOrEmpty(principalId))
            {
                // requestUri += $"&client_id={principalId}";
                requestUri += $"&principalId={principalId}";
            }
            Log($"Requesting token from {requestUri}");
            var requestMessage = new HttpRequestMessage(HttpMethod.Get, requestUri);
            requestMessage.Headers.Add(managedIdentityAuthenticationHeader, managedIdentityAuthenticationCode);

            var handler = new HttpClientHandler();

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

        public static async Task<string> ProbeSecretAsync(Config config)
        {
            return "Secret probing removed.";
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
        public string principalId { get; set; }
        public string resourceId { get; set; }
        public string secretUrl { get; set; }
        public string apiversion { get; set; }
        public string token { get; set; }
    }
}