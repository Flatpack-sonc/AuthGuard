using AuthGuard.Core.Models;

namespace AuthGuard.Core.Suppressions;

/// <summary>Applies policy-file suppressions and baseline entries to raw findings.</summary>
public static class SuppressionEngine
{
    public sealed record ApplyResult(
        IReadOnlyList<Finding> Active,
        IReadOnlyList<SuppressedFinding> Suppressed,
        IReadOnlyList<SuppressionRule> ExpiredRules);

    public static ApplyResult Apply(
        IEnumerable<Finding> findings,
        IEnumerable<SuppressionRule>? suppressions = null,
        BaselineDocument? baseline = null,
        DateOnly? todayUtc = null)
    {
        var today = todayUtc ?? DateOnly.FromDateTime(DateTime.UtcNow);
        var list = findings.ToList();
        var suppressed = new List<SuppressedFinding>();
        var active = new List<Finding>();
        var matchedIds = new HashSet<Finding>(ReferenceEqualityComparer.Instance);
        var expired = new List<SuppressionRule>();

        var rules = (suppressions ?? Array.Empty<SuppressionRule>()).ToList();
        foreach (var rule in rules.Where(r => r.Until is not null && r.Until < today))
        {
            expired.Add(rule);
        }

        var liveRules = rules.Where(r => r.Until is null || r.Until >= today).ToList();

        foreach (var finding in list)
        {
            var rule = liveRules.FirstOrDefault(r => Matches(r, finding));
            if (rule is not null)
            {
                suppressed.Add(new SuppressedFinding
                {
                    Finding = finding,
                    Reason = rule.Reason,
                    Source = SuppressionSource.PolicyFile,
                    Until = rule.Until,
                    Ticket = rule.Ticket
                });
                matchedIds.Add(finding);
                continue;
            }

            if (baseline is not null)
            {
                var entry = baseline.Findings.FirstOrDefault(b =>
                    string.Equals(b.Id, finding.Id, StringComparison.OrdinalIgnoreCase)
                    && (b.Severity is null || b.Severity == finding.Severity));

                if (entry is not null)
                {
                    suppressed.Add(new SuppressedFinding
                    {
                        Finding = finding,
                        Reason = entry.Reason
                                 ?? "Accepted in baseline snapshot (authguard baseline / --write-baseline).",
                        Source = SuppressionSource.Baseline,
                        Ticket = null
                    });
                    matchedIds.Add(finding);
                    continue;
                }
            }

            active.Add(finding);
        }

        // Surface expired suppressions that would have matched (informational for operators)
        foreach (var rule in expired)
        {
            var hit = list.FirstOrDefault(f => MatchesIgnoringExpiry(rule, f) && !matchedIds.Contains(f));
            if (hit is null)
            {
                continue;
            }

            // Don't suppress — but callers can log ExpiredRules. Finding stays active.
        }

        return new ApplyResult(active, suppressed, expired);
    }

    private static bool Matches(SuppressionRule rule, Finding finding) =>
        MatchesIgnoringExpiry(rule, finding);

    private static bool MatchesIgnoringExpiry(SuppressionRule rule, Finding finding)
    {
        if (!string.Equals(rule.Id, finding.Id, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (rule.OnlySeverity is { } sev && finding.Severity != sev)
        {
            return false;
        }

        return true;
    }

    private sealed class ReferenceEqualityComparer : IEqualityComparer<Finding>
    {
        public static readonly ReferenceEqualityComparer Instance = new();
        public bool Equals(Finding? x, Finding? y) => ReferenceEquals(x, y);
        public int GetHashCode(Finding obj) => System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(obj);
    }
}
