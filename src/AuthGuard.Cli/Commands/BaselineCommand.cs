using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using AuthGuard.Core.Baseline;
using AuthGuard.Reporting;
using Spectre.Console;
using Spectre.Console.Cli;

namespace AuthGuard.Cli.Commands;

public sealed class BaselineSettings : CommandSettings
{
    [CommandArgument(0, "<report.json>")]
    [Description("AuthGuard JSON report to freeze as baseline")]
    public string Report { get; init; } = "";

    [CommandOption("-o|--output <PATH>")]
    [Description("Baseline output path (default: .authguard-baseline.json)")]
    [DefaultValue(".authguard-baseline.json")]
    public string Output { get; init; } = ".authguard-baseline.json";

    [CommandOption("--include-suppressed")]
    [Description("Also freeze findings listed under suppressedFindings")]
    [DefaultValue(false)]
    public bool IncludeSuppressed { get; init; }

    [CommandOption("--note <TEXT>")]
    [Description("Optional note stored in the baseline")]
    public string? Note { get; init; }

    public override ValidationResult Validate()
    {
        if (!File.Exists(Report))
        {
            return ValidationResult.Error($"Report not found: {Report}");
        }

        return ValidationResult.Success();
    }
}

public sealed class BaselineCommand : Command<BaselineSettings>
{
    public override int Execute([NotNull] CommandContext context, [NotNull] BaselineSettings settings)
    {
        var report = JsonReportWriter.ReadFile(settings.Report);

        var findings = report.Findings.Select(f => new Core.Models.Finding
        {
            Id = f.Id,
            Title = f.Title,
            Severity = f.Severity,
            Description = f.Description,
            Evidence = f.Evidence,
            Remediation = f.Remediation,
            References = f.References,
            RuleCategory = f.RuleCategory
        }).ToList();

        if (settings.IncludeSuppressed)
        {
            foreach (var s in report.SuppressedFindings)
            {
                findings.Add(new Core.Models.Finding
                {
                    Id = s.Finding.Id,
                    Title = s.Finding.Title,
                    Severity = s.Finding.Severity,
                    Description = s.Finding.Description,
                    Evidence = s.Finding.Evidence,
                    Remediation = s.Finding.Remediation,
                    References = s.Finding.References,
                    RuleCategory = s.Finding.RuleCategory
                });
            }
        }

        var distinct = findings
            .GroupBy(f => f.Id + "|" + f.Severity, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

        var doc = new Core.Models.BaselineDocument
        {
            Issuer = report.Issuer,
            CreatedAt = DateTimeOffset.UtcNow,
            Profile = report.Profile,
            Idp = report.Idp,
            Note = settings.Note,
            Findings = distinct.Select(f => new Core.Models.BaselineEntry
            {
                Id = f.Id,
                Severity = f.Severity,
                Title = f.Title,
                Reason = settings.Note ?? "Frozen from JSON report via authguard baseline"
            }).ToList()
        };

        BaselineStore.Save(doc, settings.Output);
        AnsiConsole.MarkupLine(
            $"[green]Baseline written to[/] {Markup.Escape(settings.Output)} ({doc.Findings.Count} entries) for {Markup.Escape(report.Issuer)}");
        return 0;
    }
}
