using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Spectre.Console;
using Spectre.Console.Cli;

namespace AuthGuard.Cli.Commands;

public sealed class VersionCommand : Command<VersionCommand.Settings>
{
    public sealed class Settings : CommandSettings;

    public override int Execute([NotNull] CommandContext context, [NotNull] Settings settings)
    {
        var version = Assembly.GetExecutingAssembly()
                          .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                          ?.InformationalVersion
                      ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
                      ?? "1.0.0";

        // Trim any SourceLink suffix
        var plus = version.IndexOf('+', StringComparison.Ordinal);
        if (plus >= 0)
        {
            version = version[..plus];
        }

        AnsiConsole.MarkupLine($"[bold]AuthGuard[/] {Markup.Escape(version)}");
        AnsiConsole.MarkupLine("[grey]Defensive OAuth 2.0 / OIDC / JWT configuration auditor[/]");
        return 0;
    }
}
