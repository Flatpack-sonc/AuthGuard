using AuthGuard.Core.Models;
using Spectre.Console;

namespace AuthGuard.Cli;

/// <summary>Beautiful Spectre.Console audit rendering.</summary>
public static class ConsoleReportRenderer
{
    public static void Render(AuditResult result)
    {
        var rule = new Rule($"[bold]AuthGuard[/] · Defensive OIDC Audit")
        {
            Justification = Justify.Left
        };
        AnsiConsole.Write(rule);
        AnsiConsole.WriteLine();

        var gradeColor = result.Grade switch
        {
            Grade.A => "green",
            Grade.B => "chartreuse1",
            Grade.C => "yellow",
            Grade.D => "orange1",
            _ => "red"
        };

        var panel = new Panel(
            new Markup(
                $"[bold]Issuer[/]: {Markup.Escape(result.Issuer)}\n" +
                $"[bold]Score[/]: {result.Score}/100   [bold]Grade[/]: [{gradeColor} bold]{result.Grade}[/]\n" +
                $"[bold]Profile[/]: {result.Profile}   [bold]IdP[/]: {result.Idp}   [bold]Audited[/]: {result.AuditedAt:u}\n" +
                $"[bold]Source[/]: {Markup.Escape(result.DiscoverySource ?? "n/a")}\n" +
                (result.PolicyFilePath is null ? "" : $"[bold]Policy[/]: {Markup.Escape(result.PolicyFilePath)}\n") +
                (result.BaselinePath is null ? "" : $"[bold]Baseline[/]: {Markup.Escape(result.BaselinePath)}\n") +
                $"[bold]Findings[/]: Crit {result.Counts.Critical} · High {result.Counts.High} · Med {result.Counts.Medium} · Low {result.Counts.Low} · Info {result.Counts.Info}" +
                (result.SuppressedFindings.Count > 0
                    ? $"   [grey](suppressed {result.SuppressedFindings.Count})[/]"
                    : "")
            ))
        {
            Header = new PanelHeader(" Summary "),
            Border = BoxBorder.Rounded,
            Padding = new Padding(1, 0, 1, 0)
        };
        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();

        if (result.Findings.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]No active findings for the selected profile / suppressions / baseline.[/]");
        }
        else
        {
            var table = new Table()
                .Border(TableBorder.Rounded)
                .AddColumn(new TableColumn("[bold]ID[/]").Centered())
                .AddColumn("[bold]Sev[/]")
                .AddColumn("[bold]Title[/]")
                .AddColumn("[bold]Remediation[/]");

            foreach (var f in result.Findings)
            {
                table.AddRow(
                    Markup.Escape(f.Id),
                    SeverityMarkup(f.Severity),
                    Markup.Escape(Truncate(f.Title, 42)),
                    Markup.Escape(Truncate(f.Remediation, 56))
                );
            }

            AnsiConsole.Write(table);
            AnsiConsole.WriteLine();

            AnsiConsole.MarkupLine("[bold]Details[/]");
            foreach (var f in result.Findings)
            {
                var color = SeverityColor(f.Severity);
                AnsiConsole.MarkupLine($"[{color} bold]{Markup.Escape(f.Id)}[/] [{color}]{f.Severity}[/] — {Markup.Escape(f.Title)}");
                AnsiConsole.MarkupLine($"  [grey]{Markup.Escape(f.Description)}[/]");
                AnsiConsole.MarkupLine($"  [bold]Evidence:[/] {Markup.Escape(Truncate(f.Evidence, 120))}");
                AnsiConsole.MarkupLine($"  [bold]Fix:[/] {Markup.Escape(f.Remediation)}");
                if (f.References.Count > 0)
                {
                    AnsiConsole.MarkupLine($"  [grey]Refs: {Markup.Escape(string.Join(" · ", f.References.Take(2)))}[/]");
                }

                AnsiConsole.WriteLine();
            }
        }

        if (result.SuppressedFindings.Count > 0)
        {
            var sup = new Table()
                .Border(TableBorder.Simple)
                .Title("[bold]Suppressed / baselined[/]")
                .AddColumn("ID")
                .AddColumn("Source")
                .AddColumn("Reason");

            foreach (var s in result.SuppressedFindings)
            {
                var reason = s.Ticket is null ? s.Reason : $"{s.Reason} ({s.Ticket})";
                if (s.Until is not null)
                {
                    reason += $" until {s.Until:yyyy-MM-dd}";
                }

                sup.AddRow(
                    Markup.Escape(s.Finding.Id),
                    Markup.Escape(s.Source.ToString()),
                    Markup.Escape(Truncate(reason, 70)));
            }

            AnsiConsole.Write(sup);
            AnsiConsole.WriteLine();
        }

        var checklist = new Table()
            .Border(TableBorder.Simple)
            .Title("[bold]Manual verification checklist[/]")
            .AddColumn("ID")
            .AddColumn("Item")
            .AddColumn("Guidance");

        foreach (var m in result.ManualChecklist)
        {
            checklist.AddRow(
                Markup.Escape(m.Id),
                Markup.Escape(m.Title),
                Markup.Escape(Truncate(m.Guidance, 70)));
        }

        AnsiConsole.Write(checklist);
        AnsiConsole.WriteLine();

        AnsiConsole.MarkupLine("[grey italic]Analysis is limited to public discovery/JWKS metadata. Not an exploit scanner.[/]");
    }

    private static string SeverityMarkup(Severity severity) =>
        $"[{SeverityColor(severity)}]{severity}[/]";

    private static string SeverityColor(Severity severity) => severity switch
    {
        Severity.Critical => "red",
        Severity.High => "orange1",
        Severity.Medium => "yellow",
        Severity.Low => "deepskyblue1",
        _ => "grey"
    };

    private static string Truncate(string value, int max)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= max)
        {
            return value;
        }

        return value[..(max - 1)] + "…";
    }
}
