namespace AuthGuard.Core.Models;

/// <summary>Policy strictness profile controlling which findings are raised and at what severity.</summary>
public enum PolicyProfile
{
    Relaxed,
    Standard,
    Strict
}
