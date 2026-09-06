namespace AuthGuard.Core.Models;

/// <summary>A single defensive configuration finding.</summary>
public sealed class Finding
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required Severity Severity { get; init; }
    public required string Description { get; init; }
    public required string Evidence { get; init; }
    public required string Remediation { get; init; }
    public IReadOnlyList<string> References { get; init; } = Array.Empty<string>();
    public string? RuleCategory { get; init; }
}
