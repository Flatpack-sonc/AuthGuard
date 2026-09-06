using System.Text.Json;
using System.Text.Json.Serialization;
using AuthGuard.Core.Models;

namespace AuthGuard.Core.Discovery;

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true
    };
}

/// <summary>Parses OIDC discovery and JWKS documents.</summary>
public static class DiscoveryDocumentParser
{
    public static OpenIdConfiguration ParseConfiguration(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        var config = JsonSerializer.Deserialize<OpenIdConfiguration>(json, JsonDefaults.Options)
                     ?? throw new InvalidOperationException("Discovery document deserialized to null.");
        config.RawJson = json;
        return config;
    }

    public static JsonWebKeySet ParseJwks(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        var jwks = JsonSerializer.Deserialize<JsonWebKeySet>(json, JsonDefaults.Options)
                   ?? throw new InvalidOperationException("JWKS document deserialized to null.");
        jwks.RawJson = json;
        return jwks;
    }

    public static string NormalizeIssuerUrl(string issuerOrUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerOrUrl);
        var trimmed = issuerOrUrl.Trim().TrimEnd('/');

        if (!trimmed.Contains("://", StringComparison.Ordinal))
        {
            trimmed = "https://" + trimmed;
        }

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException($"Invalid issuer URL: '{issuerOrUrl}'", nameof(issuerOrUrl));
        }

        return uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
    }

    public static string BuildDiscoveryUrl(string issuerUrl)
    {
        var normalized = NormalizeIssuerUrl(issuerUrl);
        if (normalized.EndsWith("/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase))
        {
            return normalized;
        }

        return normalized + "/.well-known/openid-configuration";
    }
}
