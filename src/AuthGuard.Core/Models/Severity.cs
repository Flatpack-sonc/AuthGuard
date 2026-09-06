namespace AuthGuard.Core.Models;

/// <summary>Finding severity used for scoring and CI fail-on thresholds.</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}
