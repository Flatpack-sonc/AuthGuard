using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy;

/// <summary>
/// Post-process findings for IdP deployment shape so scoring matches intent
/// (SPA vs enterprise workforce IdP) without forking every rule.
/// </summary>
public static class IdpPresetAdjuster
{
    public static IReadOnlyList<Finding> Apply(IEnumerable<Finding> findings, IdpPreset preset)
    {
        if (preset == IdpPreset.Generic)
        {
            return findings.ToList();
        }

        return findings.Select(f => Adjust(f, preset)).Where(f => f is not null).Cast<Finding>().ToList();
    }

    private static Finding? Adjust(Finding f, IdpPreset preset)
    {
        return preset switch
        {
            IdpPreset.Spa => AdjustSpa(f),
            IdpPreset.Mobile => AdjustMobile(f),
            IdpPreset.Enterprise => AdjustEnterprise(f),
            _ => f
        };
    }

    private static Finding AdjustSpa(Finding f)
    {
        // SPAs: implicit/hybrid and missing PKCE are the real pain
        if (f.Id.StartsWith("AG-FLOW-", StringComparison.OrdinalIgnoreCase)
            || f.Id.StartsWith("AG-PKCE-", StringComparison.OrdinalIgnoreCase)
            || f.Id.StartsWith("AG-GRANT-002", StringComparison.OrdinalIgnoreCase))
        {
            return WithSeverity(f, Escalate(f.Severity));
        }

        // Introspection rarely used by pure SPA stacks
        if (f.Id.StartsWith("AG-INT-", StringComparison.OrdinalIgnoreCase) && f.Severity <= Severity.Medium)
        {
            return WithSeverity(f, Severity.Info);
        }

        return f;
    }

    private static Finding AdjustMobile(Finding f)
    {
        if (f.Id.StartsWith("AG-PKCE-", StringComparison.OrdinalIgnoreCase))
        {
            return WithSeverity(f, Escalate(f.Severity));
        }

        if (f.Id.StartsWith("AG-FLOW-", StringComparison.OrdinalIgnoreCase))
        {
            return WithSeverity(f, Escalate(f.Severity));
        }

        // Native apps often skip RP-logout metadata
        if (f.Id.StartsWith("AG-LOGOUT-", StringComparison.OrdinalIgnoreCase) && f.Severity <= Severity.Low)
        {
            return WithSeverity(f, Severity.Info);
        }

        return f;
    }

    private static Finding? AdjustEnterprise(Finding f)
    {
        // Enterprise IdPs commonly advertise hybrid / legacy for compatibility.
        // Downgrade pure coexistence noise so CI is usable; keep auth/crypto serious.
        if (f.Id is "AG-FLOW-001" or "AG-GRANT-002")
        {
            return WithSeverity(f, Severity.Low);
        }

        if (f.Id.StartsWith("AG-SCOPE-", StringComparison.OrdinalIgnoreCase)
            || f.Id.StartsWith("AG-CLAIM-", StringComparison.OrdinalIgnoreCase))
        {
            return f.Severity == Severity.Info ? null : WithSeverity(f, Severity.Info);
        }

        if (f.Id.StartsWith("AG-TEA-", StringComparison.OrdinalIgnoreCase)
            || f.Id.StartsWith("AG-REV-", StringComparison.OrdinalIgnoreCase)
            || f.Id.StartsWith("AG-ISS-", StringComparison.OrdinalIgnoreCase)
            || f.Id.StartsWith("AG-ALG-", StringComparison.OrdinalIgnoreCase))
        {
            return WithSeverity(f, Escalate(f.Severity));
        }

        return f;
    }

    private static Finding WithSeverity(Finding f, Severity severity)
    {
        if (f.Severity == severity)
        {
            return f;
        }

        return new Finding
        {
            Id = f.Id,
            Title = f.Title,
            Severity = severity,
            Description = f.Description,
            Evidence = f.Evidence,
            Remediation = f.Remediation,
            References = f.References,
            RuleCategory = f.RuleCategory
        };
    }

    private static Severity Escalate(Severity s) => s switch
    {
        Severity.Info => Severity.Low,
        Severity.Low => Severity.Medium,
        Severity.Medium => Severity.High,
        Severity.High => Severity.Critical,
        _ => s
    };
}
