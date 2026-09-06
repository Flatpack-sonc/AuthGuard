using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy;

/// <summary>Profile-dependent severity and inclusion helpers.</summary>
public static class ProfileSeverity
{
    public static Severity? Escalate(PolicyProfile profile, Severity standard, Severity? strict = null, Severity? relaxed = null)
    {
        return profile switch
        {
            PolicyProfile.Strict => strict ?? EscalateUp(standard),
            PolicyProfile.Relaxed => relaxed ?? EscalateDown(standard),
            _ => standard
        };
    }

    public static bool IncludeInfo(PolicyProfile profile) => profile != PolicyProfile.Relaxed;

    public static bool IncludeLow(PolicyProfile profile) => profile != PolicyProfile.Relaxed || true;

    private static Severity EscalateUp(Severity s) => s switch
    {
        Severity.Info => Severity.Low,
        Severity.Low => Severity.Medium,
        Severity.Medium => Severity.High,
        Severity.High => Severity.Critical,
        _ => s
    };

    private static Severity EscalateDown(Severity s) => s switch
    {
        Severity.Critical => Severity.High,
        Severity.High => Severity.Medium,
        Severity.Medium => Severity.Low,
        Severity.Low => Severity.Info,
        _ => s
    };
}
