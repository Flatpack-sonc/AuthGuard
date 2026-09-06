namespace AuthGuard.Core.Models;

/// <summary>Options controlling an AuthGuard audit run.</summary>
public sealed class AuditOptions
{
    public string? IssuerUrl { get; init; }
    public string? OfflineConfigPath { get; init; }
    public string? OfflineJwksPath { get; init; }
    public PolicyProfile Profile { get; init; } = PolicyProfile.Standard;
    public IdpPreset Idp { get; init; } = IdpPreset.Generic;
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
    public bool FetchJwks { get; init; } = true;

    /// <summary>Suppression rules from .authguard.yml (already resolved for issuer).</summary>
    public IReadOnlyList<SuppressionRule> Suppressions { get; init; } = Array.Empty<SuppressionRule>();

    /// <summary>Optional baseline document to mute known findings.</summary>
    public BaselineDocument? Baseline { get; init; }

    public string? PolicyFilePath { get; init; }
    public string? BaselinePath { get; init; }
}

/// <summary>Context available to policy rules.</summary>
public sealed class AuditContext
{
    public required string RequestedIssuer { get; init; }
    public required OpenIdConfiguration Configuration { get; init; }
    public JsonWebKeySet? Jwks { get; init; }
    public required PolicyProfile Profile { get; init; }
    public IdpPreset Idp { get; init; } = IdpPreset.Generic;
    public DiscoveryDiagnostics? Diagnostics { get; init; }
    public bool IsOffline { get; init; }
}

/// <summary>Non-exploit diagnostics from discovery/TLS/HTTP plumbing.</summary>
public sealed class DiscoveryDiagnostics
{
    public bool UsedHttps { get; init; } = true;
    public string? HttpError { get; init; }
    public string? TlsError { get; init; }
    public int? StatusCode { get; init; }
    public string? JwksHttpError { get; init; }
    public int? JwksStatusCode { get; init; }
    public bool DiscoverySucceeded { get; init; } = true;
}
