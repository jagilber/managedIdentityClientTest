using System.Net.Security;
using System.Text;
using System.Web;
using Newtonsoft.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.KeyVault.Models;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.IO;
using System.Security.Cryptography.X509Certificates;

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
                        Console.WriteLine($"Failed to parse json file: {ex.Message}");
                    }
                }
            }
        }

        public static async Task Run(Config config)
        {
            AccessTokenAcquirer.config = config;
            //# '2020-05-01' # 2448 has 2024-06-11
            Console.WriteLine($"Acquiring access token using Managed Identity");

            config.token = await AcquireAccessTokenAsync(config);
            var result = await ProbeSecretAsync(config);
            Console.WriteLine($"token: {config.token}");
            Console.WriteLine($"result: {result}");
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
            var clientId = config.clientId;
            var requestUri = $"{managedIdentityEndpoint}?api-version={managedIdentityApiVersion}&resource={HttpUtility.UrlEncode(resource)}";

            if (!string.IsNullOrEmpty(clientId))
            {
                requestUri += $"&client_id={clientId}";
            }
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

            // https://stackoverflow.com/questions/38138952/bypass-invalid-ssl-certificate-in-net-core
            // handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;


            try
            {
                var response = await new HttpClient(handler).SendAsync(requestMessage)
                    .ConfigureAwait(false);

                // response.EnsureSuccessStatusCode();
                var tokenResponseString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var tokenResponseObject = JsonConvert.DeserializeObject<ManagedIdentityTokenResponse>(tokenResponseString);
                Log(LogLevel.Info, tokenResponseString);
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
            // convert the secretUrl from Uri to vault and secret name
            var secretUrl = new Uri(config.secretUrl);
            var secret = secretUrl.Segments[2].TrimEnd('/');
            var version = secretUrl.Segments[3].TrimEnd('/');
            var vault = $"{secretUrl.Scheme}://{secretUrl.Host}";
            var endpoint = config.endpoint;
            var token = config.token;
            var header = config.header;
            var kvClient = new Microsoft.Azure.KeyVault.KeyVaultClient(new Microsoft.Azure.KeyVault.KeyVaultClient.AuthenticationCallback((a, r, s) => { return AuthenticationCallbackAsync(a, r, s); }));

            Log(LogLevel.Info, $"\nRunning with configuration: \n\tobserved vault: {vault}\n\tobserved secret: {secret}\n\tMI endpoint: {endpoint}\n\tMI auth code: {token}\n\tMI auth header: {header}");
            string response = String.Empty;

            Log(LogLevel.Info, "\n== {DateTime.UtcNow.ToString()}: Probing secret...");
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
                Log(LogLevel.Info, ve.ToString());
            }
            catch (KeyVaultErrorException kvee)
            {
                response = String.Format($"encountered KeyVault exception 0x{kvee.HResult.ToString("X")} trying to access '{secret}' in vault '{vault}': {kvee.Response.ReasonPhrase} ({kvee.Response.StatusCode})");
                Log(LogLevel.Info, kvee.ToString());
            }
            catch (Exception ex)
            {
                // handle generic errors here
                response = String.Format($"encountered exception 0x{ex.HResult.ToString("X")} trying to access '{secret}' in vault '{vault}': {ex.Message}");
                // convert exception to string using ToString() for logging including stack trace and inner exceptions
                Log(LogLevel.Info, ex.ToString());
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
            requestMessage.Headers.Add("secret", $"{config.header}");
            Log(LogLevel.Verbose, $"added header 'secret':'{config.header}'");

            try
            {

                // var cert = GetCert(config.thumbprint);
                var customHandler = new HttpClientHandler();
                // customHandler.ClientCertificates.Add(cert);
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
            catch (HttpRequestException hre)
            {
                Log(LogLevel.Info, $"HTTP request exception in authentication callback: {hre.Message}");
                Log(LogLevel.Info, $"exception details: {hre.ToString()}");
                throw;
            }
            catch (Exception ex)
            {
                Log(LogLevel.Info, $"exception in authentication callback: {ex.Message}");
                Log(LogLevel.Info, $"exception details: {ex.ToString()}");
                throw;
            }
        }

        public static X509Certificate2 GetCert(string thumbprint)
        {
            X509Store store = new X509Store("MY", StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
            X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

            foreach (X509Certificate2 x509 in collection)
            {
                try
                {

                    byte[] rawdata = x509.RawData;
                    Console.WriteLine("Content Type: {0}{1}", X509Certificate2.GetCertContentType(rawdata), Environment.NewLine);
                    Console.WriteLine("Friendly Name: {0}{1}", x509.FriendlyName, Environment.NewLine);
                    Console.WriteLine("Certificate Verified?: {0}{1}", x509.Verify(), Environment.NewLine);
                    Console.WriteLine("Simple Name: {0}{1}", x509.GetNameInfo(X509NameType.SimpleName, true), Environment.NewLine);
                    Console.WriteLine("Signature Algorithm: {0}{1}", x509.SignatureAlgorithm.FriendlyName, Environment.NewLine);
                    Console.WriteLine("Public Key: {0}{1}", x509.PublicKey.Key.ToXmlString(false), Environment.NewLine);
                    Console.WriteLine("Certificate Archived?: {0}{1}", x509.Archived, Environment.NewLine);
                    Console.WriteLine("Length of Raw Data: {0}{1}", x509.RawData.Length, Environment.NewLine);
                    if (string.Compare(x509.Thumbprint, thumbprint, true) == 0)
                    {
                        store.Close();
                        return x509;
                    }

                    //    X509Certificate2UI.DisplayCertificate(x509);
                    x509.Reset();
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("Information could not be written out for this certificate.");
                    return null;
                }
            }
            store.Close();
            return null;
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
            //   if (level != LogLevel.Verbose)
            //   {
            Console.WriteLine(message);
            //   }
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