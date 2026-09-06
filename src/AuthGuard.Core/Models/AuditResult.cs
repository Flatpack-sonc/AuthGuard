namespace AuthGuard.Core.Models;

/// <summary>Complete audit result with findings, score, and manual checklist.</summary>
public sealed class AuditResult
{
    public required string Issuer { get; init; }
    public required DateTimeOffset AuditedAt { get; init; }
    public required PolicyProfile Profile { get; init; }
    public IdpPreset Idp { get; init; } = IdpPreset.Generic;

    /// <summary>Active findings (after IdP adjust + suppressions + baseline).</summary>
    public required IReadOnlyList<Finding> Findings { get; init; }

    /// <summary>Findings muted by policy file or baseline (not scored / not failing CI).</summary>
    public IReadOnlyList<SuppressedFinding> SuppressedFindings { get; init; } = Array.Empty<SuppressedFinding>();

    public IReadOnlyList<SuppressionRule> ExpiredSuppressions { get; init; } = Array.Empty<SuppressionRule>();

    public required IReadOnlyList<ManualChecklistItem> ManualChecklist { get; init; }
    public required int Score { get; init; }
    public required Grade Grade { get; init; }
    public required SeverityCounts Counts { get; init; }
    public string? DiscoverySource { get; init; }
    public OpenIdConfiguration? Configuration { get; init; }
    public string? PolicyFilePath { get; init; }
    public string? BaselinePath { get; init; }
    public string ToolVersion { get; init; } = "1.1.0";
    public IReadOnlyList<string> Assumptions { get; init; } =
    [
        "Analysis is limited to publicly advertised OIDC discovery metadata and JWKS.",
        "Runtime token issuance, redirect URI allowlists, and client registration are not inspected.",
        "Refresh token rotation and reuse detection cannot be verified from discovery alone.",
        "Findings indicate hardening best-practice gaps, not confirmed exploitable vulnerabilities.",
        "Suppressions and baselines mute findings for scoring/CI; review expiry and ownership regularly."
    ];
}

public sealed class SeverityCounts
{
    public int Critical { get; init; }
    public int High { get; init; }
    public int Medium { get; init; }
    public int Low { get; init; }
    public int Info { get; init; }

    public int Total => Critical + High + Medium + Low + Info;

    public static SeverityCounts FromFindings(IEnumerable<Finding> findings)
    {
        var list = findings.ToList();
        return new SeverityCounts
        {
            Critical = list.Count(f => f.Severity == Severity.Critical),
            High = list.Count(f => f.Severity == Severity.High),
            Medium = list.Count(f => f.Severity == Severity.Medium),
            Low = list.Count(f => f.Severity == Severity.Low),
            Info = list.Count(f => f.Severity == Severity.Info)
        };
    }
}
