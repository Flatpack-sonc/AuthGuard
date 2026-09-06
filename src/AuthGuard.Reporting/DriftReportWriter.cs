using System.Text.Json;
using AuthGuard.Core.Drift;
using AuthGuard.Core.Models;

namespace AuthGuard.Reporting;

public static class DriftReportWriter
{
    public static string WriteJson(DriftReport report)
    {
        var dto = new
        {
            schemaVersion = "1.0.0",
            comparedAt = report.ComparedAt,
            previous = report.PreviousLabel,
            current = report.CurrentLabel,
            hasRegressions = report.HasRegressions,
            summary = new
            {
                added = report.Added.Count,
                resolved = report.Resolved.Count,
                severityIncreased = report.SeverityIncreased.Count,
                severityDecreased = report.SeverityDecreased.Count,
                unchanged = report.Unchanged.Count
            },
            items = report.Items.Select(i => new
            {
                id = i.Id,
                kind = i.Kind.ToString(),
                title = i.Title,
                previousSeverity = i.PreviousSeverity?.ToString(),
                currentSeverity = i.CurrentSeverity?.ToString()
            })
        };

        return JsonSerializer.Serialize(dto, JsonReportWriter.Options);
    }

    public static int ExitCode(DriftReport report, Severity failOnAdded = Severity.High)
    {
        if (report.SeverityIncreased.Any(i => (i.CurrentSeverity ?? Severity.Info) >= failOnAdded))
        {
            return 1;
        }

        if (report.Added.Any(i => (i.CurrentSeverity ?? Severity.Info) >= failOnAdded))
        {
            return 1;
        }

        return 0;
    }

    public static IEnumerable<Finding> ToFindings(JsonAuditReport report) =>
        report.Findings.Select(f => new Finding
        {
            Id = f.Id,
            Title = f.Title,
            Severity = f.Severity,
            Description = f.Description,
            Evidence = f.Evidence,
            Remediation = f.Remediation,
            References = f.References,
            RuleCategory = f.RuleCategory
        });
}
