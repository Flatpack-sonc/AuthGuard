using System.Text.Json.Serialization;

namespace AuthGuard.Core.Models;

/// <summary>JSON Web Key Set (RFC 7517).</summary>
public sealed class JsonWebKeySet
{
    [JsonPropertyName("keys")]
    public List<JsonWebKey>? Keys { get; set; }

    [JsonIgnore]
    public string? RawJson { get; set; }
}

/// <summary>A single JWK entry.</summary>
public sealed class JsonWebKey
{
    [JsonPropertyName("kty")]
    public string? Kty { get; set; }

    [JsonPropertyName("use")]
    public string? Use { get; set; }

    [JsonPropertyName("alg")]
    public string? Alg { get; set; }

    [JsonPropertyName("kid")]
    public string? Kid { get; set; }

    [JsonPropertyName("x5t")]
    public string? X5t { get; set; }

    [JsonPropertyName("n")]
    public string? N { get; set; }

    [JsonPropertyName("e")]
    public string? E { get; set; }

    [JsonPropertyName("crv")]
    public string? Crv { get; set; }

    [JsonPropertyName("x")]
    public string? X { get; set; }

    [JsonPropertyName("y")]
    public string? Y { get; set; }

    [JsonPropertyName("k")]
    public string? K { get; set; }

    [JsonPropertyName("x5c")]
    public List<string>? X5c { get; set; }
}
