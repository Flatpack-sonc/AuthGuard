namespace AuthGuard.Core.Models;

/// <summary>How a finding was muted for scoring / CI.</summary>
public enum SuppressionSource
{
    PolicyFile,
    Baseline,
    Expired
}

/// <summary>A finding that was matched by a suppression or baseline entry.</summary>
public sealed class SuppressedFinding
{
    public required Finding Finding { get; init; }
    public required string Reason { get; init; }
    public required SuppressionSource Source { get; init; }
    public DateOnly? Until { get; init; }
    public string? Ticket { get; init; }
}

/// <summary>Single suppression rule from .authguard.yml.</summary>
public sealed class SuppressionRule
{
    /// <summary>Finding ID, e.g. AG-PKCE-001. Case-insensitive.</summary>
    public required string Id { get; init; }

    /// <summary>Required human-readable justification (CI-friendly audit trail).</summary>
    public required string Reason { get; init; }

    /// <summary>Optional expiry (UTC date). After this date the suppression no longer applies.</summary>
    public DateOnly? Until { get; init; }

    /// <summary>Optional ticket / issue reference.</summary>
    public string? Ticket { get; init; }

    /// <summary>If set, only suppress when finding severity equals this value.</summary>
    public Severity? OnlySeverity { get; init; }
}

/// <summary>Fingerprint of an accepted finding in a baseline snapshot.</summary>
public sealed class BaselineEntry
{
    public required string Id { get; init; }
    public Severity? Severity { get; init; }
    public string? Title { get; init; }
    public string? Reason { get; init; }
}

/// <summary>Persisted baseline file (.authguard-baseline.json).</summary>
public sealed class BaselineDocument
{
    public string SchemaVersion { get; init; } = "1.0.0";
    public string Tool { get; init; } = "AuthGuard";
    public string? Issuer { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public PolicyProfile? Profile { get; init; }
    public IdpPreset? Idp { get; init; }
    public string? Note { get; init; }
    public IReadOnlyList<BaselineEntry> Findings { get; init; } = Array.Empty<BaselineEntry>();
}
