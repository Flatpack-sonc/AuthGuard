namespace AuthGuard.Core.Config;

using AuthGuard.Core.Models;

/// <summary>Root schema for .authguard.yml (policy file).</summary>
public sealed class AuthGuardPolicyFile
{
    public string? Profile { get; set; }
    public string? Idp { get; set; }
    public string? FailOn { get; set; }
    public string? Baseline { get; set; }
    public List<SuppressionYaml> Suppressions { get; set; } = [];
    public List<IssuerOverrideYaml> Issuers { get; set; } = [];
}

public sealed class SuppressionYaml
{
    public string? Id { get; set; }
    public string? Reason { get; set; }
    public string? Until { get; set; }
    public string? Ticket { get; set; }
    public string? OnlySeverity { get; set; }
}

public sealed class IssuerOverrideYaml
{
    public string? Url { get; set; }
    public string? Profile { get; set; }
    public string? Idp { get; set; }
    public List<SuppressionYaml> Suppressions { get; set; } = [];
}

/// <summary>Resolved, typed policy ready for the engine.</summary>
public sealed class ResolvedPolicy
{
    public string? SourcePath { get; init; }
    public PolicyProfile? Profile { get; init; }
    public IdpPreset? Idp { get; init; }
    public Severity? FailOn { get; init; }
    public string? BaselinePath { get; init; }
    public IReadOnlyList<SuppressionRule> Suppressions { get; init; } = Array.Empty<SuppressionRule>();
}
