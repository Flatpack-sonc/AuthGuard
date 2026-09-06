using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using AuthGuard.Core.Baseline;
using AuthGuard.Core.Models;
using AuthGuard.Reporting;
using Spectre.Console;
using Spectre.Console.Cli;

namespace AuthGuard.Cli.Commands;

public sealed class AuditSettings : CommandSettings
{
    [CommandArgument(0, "[issuer]")]
    [Description("OIDC issuer URL (or discovery URL). Optional when --config is provided.")]
    public string? Issuer { get; init; }

    [CommandOption("-p|--profile <PROFILE>")]
    [Description("Policy profile: strict | standard | relaxed (overrides .authguard.yml when set)")]
    [DefaultValue("standard")]
    public string Profile { get; init; } = "standard";

    [CommandOption("--idp <PRESET>")]
    [Description("IdP preset: generic | spa | mobile | enterprise")]
    public string? Idp { get; init; }

    [CommandOption("-f|--format <FORMAT>")]
    [Description("Output format: console | json | sarif | html (default: console)")]
    [DefaultValue("console")]
    public string Format { get; init; } = "console";

    [CommandOption("-o|--output <PATH>")]
    [Description("Write report to file (recommended for json/sarif/html)")]
    public string? Output { get; init; }

    [CommandOption("--fail-on <SEVERITY>")]
    [Description("Non-zero exit if active findings ≥ severity (default: high, or fail_on from policy file)")]
    [DefaultValue("high")]
    public string FailOn { get; init; } = "high";

    [CommandOption("--timeout <SECONDS>")]
    [Description("HTTP timeout in seconds (default: 30)")]
    [DefaultValue(30)]
    public int TimeoutSeconds { get; init; } = 30;

    [CommandOption("-c|--config <PATH>")]
    [Description("Offline mode: path to a saved OpenID discovery JSON document")]
    public string? Config { get; init; }

    [CommandOption("--jwks <PATH>")]
    [Description("Optional offline JWKS JSON path (used with --config)")]
    public string? Jwks { get; init; }

    [CommandOption("--policy-file <PATH>")]
    [Description("Path to .authguard.yml (default: walk up from cwd)")]
    public string? PolicyFile { get; init; }

    [CommandOption("--no-policy-file")]
    [Description("Ignore .authguard.yml auto-discovery")]
    [DefaultValue(false)]
    public bool NoPolicyFile { get; init; }

    [CommandOption("--baseline <PATH>")]
    [Description("Baseline JSON to mute known findings (overrides policy baseline path)")]
    public string? Baseline { get; init; }

    [CommandOption("--write-baseline <PATH>")]
    [Description("After audit, write a baseline snapshot of current active findings")]
    public string? WriteBaseline { get; init; }

    [CommandOption("--write-baseline-all <PATH>")]
    [Description("Write baseline including currently suppressed findings")]
    public string? WriteBaselineAll { get; init; }

    [CommandOption("--no-color")]
    [Description("Disable ANSI colors")]
    [DefaultValue(false)]
    public bool NoColor { get; init; }

    // Spectre does not tell us if default was used; we detect via remaining raw args in command.
    public bool ProfileExplicit { get; set; }
    public bool FailOnExplicit { get; set; }

    public override ValidationResult Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer) && string.IsNullOrWhiteSpace(Config))
        {
            return ValidationResult.Error("Provide an issuer URL argument or --config for offline mode.");
        }

        if (!Enum.TryParse<PolicyProfile>(Profile, ignoreCase: true, out _))
        {
            return ValidationResult.Error("Invalid --profile. Use strict, standard, or relaxed.");
        }

        if (!string.IsNullOrWhiteSpace(Idp) && !Enum.TryParse<IdpPreset>(Idp, ignoreCase: true, out _))
        {
            return ValidationResult.Error("Invalid --idp. Use generic, spa, mobile, or enterprise.");
        }

        if (!ReportFormatParser.TryParse(Format, out _))
        {
            return ValidationResult.Error("Invalid --format. Use console, json, sarif, or html.");
        }

        if (!ExitCodeEvaluator.TryParseFailOn(FailOn, out _))
        {
            return ValidationResult.Error("Invalid --fail-on. Use critical, high, medium, low, or info.");
        }

        if (TimeoutSeconds <= 0)
        {
            return ValidationResult.Error("--timeout must be a positive number of seconds.");
        }

        if (!string.IsNullOrWhiteSpace(Config) && !File.Exists(Config))
        {
            return ValidationResult.Error($"Config file not found: {Config}");
        }

        if (!string.IsNullOrWhiteSpace(Jwks) && !File.Exists(Jwks))
        {
            return ValidationResult.Error($"JWKS file not found: {Jwks}");
        }

        return ValidationResult.Success();
    }
}

public sealed class AuditCommand : AsyncCommand<AuditSettings>
{
    public override async Task<int> ExecuteAsync(
        [NotNull] CommandContext context,
        [NotNull] AuditSettings settings)
    {
        if (settings.NoColor)
        {
            AnsiConsole.Profile.Capabilities.ColorSystem = ColorSystem.NoColors;
        }

        // Detect explicit CLI overrides from remaining/raw args
        var args = context.Remaining.Raw.Concat(Environment.GetCommandLineArgs()).ToArray();
        var profileExplicit = args.Any(a =>
            a.Equals("--profile", StringComparison.OrdinalIgnoreCase)
            || a.StartsWith("--profile=", StringComparison.OrdinalIgnoreCase)
            || a.Equals("-p", StringComparison.OrdinalIgnoreCase));
        var failOnExplicit = args.Any(a =>
            a.Equals("--fail-on", StringComparison.OrdinalIgnoreCase)
            || a.StartsWith("--fail-on=", StringComparison.OrdinalIgnoreCase));

        ReportFormatParser.TryParse(settings.Format, out var format);

        AuditResult result;
        Severity failOn;
        try
        {
            var bundle = AuditPipeline.Build(
                settings.Issuer,
                settings.Config,
                settings.Jwks,
                settings.Profile,
                profileExplicit,
                settings.Idp,
                settings.FailOn,
                failOnExplicit,
                settings.TimeoutSeconds,
                settings.PolicyFile,
                settings.Baseline,
                settings.NoPolicyFile);

            failOn = bundle.FailOn;
            var spinner = format == ReportFormat.Console && !settings.NoColor;
            result = await AuditPipeline.ExecuteAsync(bundle.Options, spinner).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Audit failed:[/] {Markup.Escape(ex.Message)}");
            return 2;
        }

        try
        {
            if (!string.IsNullOrWhiteSpace(settings.WriteBaseline))
            {
                var doc = BaselineStore.FromAuditResult(result);
                BaselineStore.Save(doc, settings.WriteBaseline);
                AnsiConsole.MarkupLine($"[green]Baseline written to[/] {Markup.Escape(settings.WriteBaseline)} ({doc.Findings.Count} findings)");
            }

            if (!string.IsNullOrWhiteSpace(settings.WriteBaselineAll))
            {
                var doc = BaselineStore.FromAuditIncludingSuppressed(result);
                BaselineStore.Save(doc, settings.WriteBaselineAll);
                AnsiConsole.MarkupLine($"[green]Baseline (incl. suppressed) written to[/] {Markup.Escape(settings.WriteBaselineAll)} ({doc.Findings.Count} findings)");
            }

            Render(result, format, settings.Output);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Failed to write report:[/] {Markup.Escape(ex.Message)}");
            return 2;
        }

        if (result.ExpiredSuppressions.Count > 0)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Warning:[/] {result.ExpiredSuppressions.Count} suppression(s) expired — findings may have returned.");
        }

        return ExitCodeEvaluator.FromFindings(result.Findings, failOn);
    }

    private static void Render(AuditResult result, ReportFormat format, string? outputPath)
    {
        switch (format)
        {
            case ReportFormat.Json:
            {
                var json = JsonReportWriter.Write(result);
                if (!string.IsNullOrWhiteSpace(outputPath))
                {
                    File.WriteAllText(outputPath, json);
                    AnsiConsole.MarkupLine($"[green]JSON report written to[/] {Markup.Escape(outputPath)}");
                }
                else
                {
                    AnsiConsole.WriteLine(json);
                }

                break;
            }
            case ReportFormat.Sarif:
            {
                var sarif = SarifReportWriter.Write(result);
                var path = string.IsNullOrWhiteSpace(outputPath) ? "authguard.sarif" : outputPath;
                File.WriteAllText(path, sarif);
                AnsiConsole.MarkupLine($"[green]SARIF report written to[/] {Markup.Escape(path)}");
                break;
            }
            case ReportFormat.Html:
            {
                var path = string.IsNullOrWhiteSpace(outputPath) ? "authguard-report.html" : outputPath;
                HtmlReportWriter.WriteToFile(result, path);
                AnsiConsole.MarkupLine($"[green]HTML report written to[/] {Markup.Escape(path)}");
                break;
            }
            default:
                ConsoleReportRenderer.Render(result);
                if (!string.IsNullOrWhiteSpace(outputPath))
                {
                    File.WriteAllText(outputPath, JsonReportWriter.Write(result));
                    AnsiConsole.MarkupLine($"[grey]Also wrote JSON snapshot to[/] {Markup.Escape(outputPath)}");
                }

                break;
        }
    }
}
