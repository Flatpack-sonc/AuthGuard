using AuthGuard.Core.Models;

namespace AuthGuard.Core.Discovery;

/// <summary>Result of fetching OIDC discovery (+ optional JWKS).</summary>
public sealed class DiscoveryFetchResult
{
    public OpenIdConfiguration? Configuration { get; init; }
    public JsonWebKeySet? Jwks { get; init; }
    public required DiscoveryDiagnostics Diagnostics { get; init; }
    public required string Source { get; init; }
    public bool Success => Configuration is not null && Diagnostics.DiscoverySucceeded;
}

/// <summary>Fetches public OIDC discovery metadata and JWKS (defensive read-only).</summary>
public sealed class DiscoveryClient
{
    private readonly HttpClient _httpClient;

    public DiscoveryClient(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? CreateDefaultClient();
    }

    public static HttpClient CreateDefaultClient(TimeSpan? timeout = null)
    {
        var client = new HttpClient
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(30)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("AuthGuard/1.0 (+https://github.com/authguard; defensive-oidc-auditor)");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        return client;
    }

    public async Task<DiscoveryFetchResult> FetchAsync(
        string issuerOrUrl,
        bool fetchJwks = true,
        CancellationToken cancellationToken = default)
    {
        var discoveryUrl = DiscoveryDocumentParser.BuildDiscoveryUrl(issuerOrUrl);
        var usedHttps = discoveryUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        try
        {
            using var response = await _httpClient.GetAsync(discoveryUrl, cancellationToken).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return new DiscoveryFetchResult
                {
                    Source = discoveryUrl,
                    Diagnostics = new DiscoveryDiagnostics
                    {
                        UsedHttps = usedHttps,
                        DiscoverySucceeded = false,
                        StatusCode = (int)response.StatusCode,
                        HttpError = $"HTTP {(int)response.StatusCode} {response.ReasonPhrase} fetching discovery document."
                    }
                };
            }

            OpenIdConfiguration config;
            try
            {
                config = DiscoveryDocumentParser.ParseConfiguration(body);
            }
            catch (Exception ex)
            {
                return new DiscoveryFetchResult
                {
                    Source = discoveryUrl,
                    Diagnostics = new DiscoveryDiagnostics
                    {
                        UsedHttps = usedHttps,
                        DiscoverySucceeded = false,
                        StatusCode = (int)response.StatusCode,
                        HttpError = $"Failed to parse discovery JSON: {ex.Message}"
                    }
                };
            }

            JsonWebKeySet? jwks = null;
            string? jwksError = null;
            int? jwksStatus = null;

            if (fetchJwks && !string.IsNullOrWhiteSpace(config.JwksUri))
            {
                try
                {
                    using var jwksResponse = await _httpClient.GetAsync(config.JwksUri, cancellationToken).ConfigureAwait(false);
                    jwksStatus = (int)jwksResponse.StatusCode;
                    var jwksBody = await jwksResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                    if (jwksResponse.IsSuccessStatusCode)
                    {
                        jwks = DiscoveryDocumentParser.ParseJwks(jwksBody);
                    }
                    else
                    {
                        jwksError = $"HTTP {jwksStatus} {jwksResponse.ReasonPhrase} fetching JWKS.";
                    }
                }
                catch (Exception ex)
                {
                    jwksError = $"JWKS fetch failed: {ex.Message}";
                }
            }

            return new DiscoveryFetchResult
            {
                Configuration = config,
                Jwks = jwks,
                Source = discoveryUrl,
                Diagnostics = new DiscoveryDiagnostics
                {
                    UsedHttps = usedHttps,
                    DiscoverySucceeded = true,
                    StatusCode = (int)response.StatusCode,
                    JwksHttpError = jwksError,
                    JwksStatusCode = jwksStatus
                }
            };
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new DiscoveryFetchResult
            {
                Source = discoveryUrl,
                Diagnostics = new DiscoveryDiagnostics
                {
                    UsedHttps = usedHttps,
                    DiscoverySucceeded = false,
                    HttpError = $"Request timed out after {_httpClient.Timeout.TotalSeconds:0}s."
                }
            };
        }
        catch (HttpRequestException ex)
        {
            var isTls = LooksLikeTlsError(ex);
            return new DiscoveryFetchResult
            {
                Source = discoveryUrl,
                Diagnostics = new DiscoveryDiagnostics
                {
                    UsedHttps = usedHttps,
                    DiscoverySucceeded = false,
                    HttpError = isTls ? null : ex.Message,
                    TlsError = isTls ? ex.Message : null
                }
            };
        }
        catch (Exception ex)
        {
            return new DiscoveryFetchResult
            {
                Source = discoveryUrl,
                Diagnostics = new DiscoveryDiagnostics
                {
                    UsedHttps = usedHttps,
                    DiscoverySucceeded = false,
                    HttpError = ex.Message
                }
            };
        }
    }

    public static DiscoveryFetchResult LoadOffline(string configPath, string? jwksPath = null)
    {
        var json = File.ReadAllText(configPath);
        var config = DiscoveryDocumentParser.ParseConfiguration(json);
        JsonWebKeySet? jwks = null;
        string? jwksError = null;

        if (!string.IsNullOrWhiteSpace(jwksPath))
        {
            try
            {
                jwks = DiscoveryDocumentParser.ParseJwks(File.ReadAllText(jwksPath));
            }
            catch (Exception ex)
            {
                jwksError = $"Offline JWKS parse failed: {ex.Message}";
            }
        }

        var issuer = config.Issuer ?? Path.GetFileNameWithoutExtension(configPath);
        var usedHttps = (config.Issuer ?? string.Empty).StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        return new DiscoveryFetchResult
        {
            Configuration = config,
            Jwks = jwks,
            Source = $"offline:{configPath}",
            Diagnostics = new DiscoveryDiagnostics
            {
                UsedHttps = usedHttps || string.IsNullOrEmpty(config.Issuer),
                DiscoverySucceeded = true,
                JwksHttpError = jwksError
            }
        };
    }

    private static bool LooksLikeTlsError(HttpRequestException ex)
    {
        var msg = ex.ToString();
        return msg.Contains("SSL", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("TLS", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("certificate", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("trust", StringComparison.OrdinalIgnoreCase);
    }
}
