using AuthGuard.Cli.Commands;
using Spectre.Console.Cli;

var app = new CommandApp();
app.Configure(config =>
{
    config.SetApplicationName("authguard");
    config.ValidateExamples();

    config.AddCommand<AuditCommand>("audit")
        .WithDescription("Audit an OAuth/OIDC issuer configuration (defensive checks only)")
        .WithExample("audit", "https://login.microsoftonline.com/common/v2.0")
        .WithExample("audit", "https://accounts.google.com", "--profile", "strict", "--idp", "spa")
        .WithExample("audit", "--config", "discovery.json", "--format", "sarif", "--output", "authguard.sarif")
        .WithExample("audit", "https://example.com", "--policy-file", ".authguard.yml", "--write-baseline", ".authguard-baseline.json");

    config.AddCommand<DiffCommand>("diff")
        .WithDescription("Compare two AuthGuard JSON reports (drift / regressions)")
        .WithExample("diff", "yesterday.json", "today.json", "--fail-on", "high");

    config.AddCommand<BaselineCommand>("baseline")
        .WithDescription("Freeze a JSON report into .authguard-baseline.json")
        .WithExample("baseline", "report.json", "-o", ".authguard-baseline.json");

    config.AddCommand<InitCommand>("init")
        .WithDescription("Create a sample .authguard.yml policy file")
        .WithExample("init");

    config.AddCommand<VersionCommand>("version")
        .WithDescription("Show AuthGuard version");
});

return await app.RunAsync(args);
