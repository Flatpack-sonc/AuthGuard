using AuthGuard.Core.Models;

namespace AuthGuard.Reporting;

/// <summary>CI exit-code helpers based on --fail-on threshold.</summary>
public static class ExitCodeEvaluator
{
    /// <summary>
    /// 0 = success / below threshold,
    /// 1 = findings at or above fail-on severity,
    /// 2 = tool/runtime error (caller).
    /// </summary>
    public static int FromFindings(IEnumerable<Finding> findings, Severity failOn)
    {
        return findings.Any(f => f.Severity >= failOn) ? 1 : 0;
    }

    public static bool TryParseFailOn(string? value, out Severity severity)
    {
        severity = Severity.High;
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        return Enum.TryParse(value.Trim(), ignoreCase: true, out severity);
    }
}
