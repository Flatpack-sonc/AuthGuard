using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using AuthGuard.Core.Config;
using Spectre.Console;
using Spectre.Console.Cli;

namespace AuthGuard.Cli.Commands;

public sealed class InitSettings : CommandSettings
{
    [CommandOption("-f|--force")]
    [Description("Overwrite existing .authguard.yml")]
    [DefaultValue(false)]
    public bool Force { get; init; }

    [CommandOption("-o|--output <PATH>")]
    [Description("Output path (default: ./.authguard.yml)")]
    public string? Output { get; init; }
}

public sealed class InitCommand : Command<InitSettings>
{
    public override int Execute([NotNull] CommandContext context, [NotNull] InitSettings settings)
    {
        var path = string.IsNullOrWhiteSpace(settings.Output)
            ? Path.Combine(Directory.GetCurrentDirectory(), PolicyFileLoader.DefaultFileName)
            : Path.GetFullPath(settings.Output);

        if (File.Exists(path) && !settings.Force)
        {
            AnsiConsole.MarkupLine($"[yellow]Already exists:[/] {Markup.Escape(path)} (use --force to overwrite)");
            return 1;
        }

        File.WriteAllText(path, PolicyFileLoader.CreateSampleYaml());
        AnsiConsole.MarkupLine($"[green]Wrote[/] {Markup.Escape(path)}");
        AnsiConsole.MarkupLine("[grey]Edit suppressions, set idp/profile, then run: authguard audit <issuer>[/]");
        return 0;
    }
}
