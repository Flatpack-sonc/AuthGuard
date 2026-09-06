namespace AuthGuard.Core.Models;

/// <summary>
/// Client/IdP deployment shape. Adjusts severity emphasis after rules run
/// so enterprise multi-tenant IdPs and SPA stacks are not scored identically.
/// </summary>
public enum IdpPreset
{
    /// <summary>No IdP-specific adjustments.</summary>
    Generic = 0,

    /// <summary>Browser SPA / public clients — PKCE and implicit/hybrid are critical.</summary>
    Spa,

    /// <summary>Native mobile public clients — PKCE and redirect hygiene emphasis.</summary>
    Mobile,

    /// <summary>
    /// Enterprise / workforce IdP (Entra, Okta workforce, etc.).
    /// Legacy coexistence flows are expected noise; client auth &amp; revocation matter more.
    /// </summary>
    Enterprise
}
