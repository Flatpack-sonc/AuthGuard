using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using AuthGuard.Core.Drift;
using AuthGuard.Core.Models;
using AuthGuard.Reporting;
using Spectre.Console;
using Spectre.Console.Cli;

namespace AuthGuard.Cli.Commands;

public sealed class DiffSettings : CommandSettings
{
    [CommandArgument(0, "<previous>")]
    [Description("Previous AuthGuard JSON report path")]
    public string Previous { get; init; } = "";

    [CommandArgument(1, "<current>")]
    [Description("Current AuthGuard JSON report path")]
    public string Current { get; init; } = "";

    [CommandOption("--fail-on <SEVERITY>")]
    [Description("Fail if added/increased findings ≥ severity (default: high)")]
    [DefaultValue("high")]
    public string FailOn { get; init; } = "high";

    [CommandOption("-f|--format <FORMAT>")]
    [Description("console | json (default: console)")]
    [DefaultValue("console")]
    public string Format { get; init; } = "console";

    [CommandOption("-o|--output <PATH>")]
    [Description("Write JSON drift report to file")]
    public string? Output { get; init; }

    public override ValidationResult Validate()
    {
        if (!File.Exists(Previous))
        {
            return ValidationResult.Error($"Previous report not found: {Previous}");
        }

        if (!File.Exists(Current))
        {
            return ValidationResult.Error($"Current report not found: {Current}");
        }

        if (!ExitCodeEvaluator.TryParseFailOn(FailOn, out _))
        {
            return ValidationResult.Error("Invalid --fail-on.");
        }

        return ValidationResult.Success();
    }
}

public sealed class DiffCommand : Command<DiffSettings>
{
    public override int Execute([NotNull] CommandContext context, [NotNull] DiffSettings settings)
    {
        ExitCodeEvaluator.TryParseFailOn(settings.FailOn, out var failOn);

        var prev = JsonReportWriter.ReadFile(settings.Previous);
        var curr = JsonReportWriter.ReadFile(settings.Current);

        var report = DriftComparer.CompareFindings(
            DriftReportWriter.ToFindings(prev),
            DriftReportWriter.ToFindings(curr),
            settings.Previous,
            settings.Current);

        if (string.Equals(settings.Format, "json", StringComparison.OrdinalIgnoreCase))
        {
            var json = DriftReportWriter.WriteJson(report);
            if (!string.IsNullOrWhiteSpace(settings.Output))
            {
                File.WriteAllText(settings.Output, json);
                AnsiConsole.MarkupLine($"[green]Drift JSON written to[/] {Markup.Escape(settings.Output)}");
            }
            else
            {
                AnsiConsole.WriteLine(json);
            }
        }
        else
        {
            RenderConsole(report);
            if (!string.IsNullOrWhiteSpace(settings.Output))
            {
                File.WriteAllText(settings.Output, DriftReportWriter.WriteJson(report));
                AnsiConsole.MarkupLine($"[grey]Also wrote JSON to[/] {Markup.Escape(settings.Output)}");
            }
        }

        return DriftReportWriter.ExitCode(report, failOn);
    }

    private static void RenderConsole(DriftReport report)
    {
        var rule = new Rule("[bold]AuthGuard drift[/]") { Justification = Justify.Left };
        AnsiConsole.Write(rule);
        AnsiConsole.WriteLine();

        var panel = new Panel(
            new Markup(
                $"[bold]Previous[/]: {Markup.Escape(report.PreviousLabel)}\n" +
                $"[bold]Current[/]:  {Markup.Escape(report.CurrentLabel)}\n" +
                $"[bold]Added[/]: {report.Added.Count}  [bold]Resolved[/]: {report.Resolved.Count}  " +
                $"[bold]↑Sev[/]: {report.SeverityIncreased.Count}  [bold]↓Sev[/]: {report.SeverityDecreased.Count}  " +
                $"[bold]Same[/]: {report.Unchanged.Count}\n" +
                (report.HasRegressions
                    ? "[red bold]Regressions detected[/]"
                    : "[green]No regressions (no new/raised findings)[/]")))
        {
            Header = new PanelHeader(" Diff summary "),
            Border = BoxBorder.Rounded
        };
        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();

        void Section(string title, IReadOnlyList<DriftItem> items, string color)
        {
            if (items.Count == 0)
            {
                return;
            }

            AnsiConsole.MarkupLine($"[{color} bold]{title}[/]");
            foreach (var i in items)
            {
                var sev = i.Kind switch
                {
                    DriftChangeKind.Added => i.CurrentSeverity?.ToString() ?? "?",
                    DriftChangeKind.Resolved => i.PreviousSeverity?.ToString() ?? "?",
                    _ => $"{i.PreviousSeverity} → {i.CurrentSeverity}"
                };
                AnsiConsole.MarkupLine($"  {Markup.Escape(i.Id)} [{color}]{sev}[/]  {Markup.Escape(i.Title ?? "")}");
            }

            AnsiConsole.WriteLine();
        }

        Section("Added", report.Added, "red");
        Section("Severity increased", report.SeverityIncreased, "orange1");
        Section("Resolved", report.Resolved, "green");
        Section("Severity decreased", report.SeverityDecreased, "deepskyblue1");
    }
}
