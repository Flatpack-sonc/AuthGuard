using AuthGuard.Core;
using AuthGuard.Core.Baseline;
using AuthGuard.Core.Config;
using AuthGuard.Core.Discovery;
using AuthGuard.Core.Models;
using AuthGuard.Reporting;
using Spectre.Console;

namespace AuthGuard.Cli;

/// <summary>Resolve .authguard.yml + baseline into AuditOptions.</summary>
public static class AuditPipeline
{
    public sealed record Bundle(AuditOptions Options, Severity FailOn);

    public static Bundle Build(
        string? issuer,
        string? offlineConfig,
        string? offlineJwks,
        string profileCli,
        bool profileCliExplicit,
        string? idpCli,
        string failOnCli,
        bool failOnCliExplicit,
        int timeoutSeconds,
        string? policyFileCli,
        string? baselineCli,
        bool ignorePolicyFile)
    {
        ResolvedPolicy? policy = null;
        string? policyPath = null;

        if (!ignorePolicyFile)
        {
            policyPath = !string.IsNullOrWhiteSpace(policyFileCli)
                ? Path.GetFullPath(policyFileCli)
                : PolicyFileLoader.FindDefault();

            if (policyPath is not null)
            {
                if (!File.Exists(policyPath))
                {
                    throw new FileNotFoundException($"Policy file not found: {policyPath}", policyPath);
                }

                var issuerHint = issuer ?? TryReadIssuerFromDiscovery(offlineConfig);
                policy = PolicyFileLoader.Resolve(PolicyFileLoader.Load(policyPath), issuerHint, policyPath);
            }
        }

        var profile = profileCliExplicit || policy?.Profile is null
            ? Enum.Parse<PolicyProfile>(profileCli, ignoreCase: true)
            : policy.Profile.Value;

        IdpPreset idp;
        if (!string.IsNullOrWhiteSpace(idpCli))
        {
            if (!Enum.TryParse(idpCli, ignoreCase: true, out idp))
            {
                throw new ArgumentException($"Invalid --idp '{idpCli}'. Use generic, spa, mobile, enterprise.");
            }
        }
        else
        {
            idp = policy?.Idp ?? IdpPreset.Generic;
        }

        if (!ExitCodeEvaluator.TryParseFailOn(failOnCli, out var failOn))
        {
            throw new ArgumentException($"Invalid --fail-on '{failOnCli}'.");
        }

        if (!failOnCliExplicit && policy?.FailOn is { } policyFailOn)
        {
            failOn = policyFailOn;
        }

        string? baselinePath = !string.IsNullOrWhiteSpace(baselineCli)
            ? Path.GetFullPath(baselineCli)
            : policy?.BaselinePath;

        BaselineDocument? baseline = null;
        string? loadedBaselinePath = null;
        if (!string.IsNullOrWhiteSpace(baselinePath) && File.Exists(baselinePath))
        {
            baseline = BaselineStore.Load(baselinePath);
            loadedBaselinePath = baselinePath;
        }

        var options = new AuditOptions
        {
            IssuerUrl = issuer,
            OfflineConfigPath = offlineConfig,
            OfflineJwksPath = offlineJwks,
            Profile = profile,
            Idp = idp,
            Timeout = TimeSpan.FromSeconds(timeoutSeconds),
            Suppressions = policy?.Suppressions ?? Array.Empty<SuppressionRule>(),
            Baseline = baseline,
            PolicyFilePath = policyPath,
            BaselinePath = loadedBaselinePath
        };

        return new Bundle(options, failOn);
    }

    public static async Task<AuditResult> ExecuteAsync(AuditOptions options, bool spinner)
    {
        async Task<AuditResult> Run()
        {
            var http = DiscoveryClient.CreateDefaultClient(options.Timeout);
            var service = new AuditService(new DiscoveryClient(http));
            return await service.AuditAsync(options).ConfigureAwait(false);
        }

        if (!spinner)
        {
            return await Run().ConfigureAwait(false);
        }

        return await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Auditing OIDC configuration...", async _ => await Run().ConfigureAwait(false))
            .ConfigureAwait(false);
    }

    private static string? TryReadIssuerFromDiscovery(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path));
            return doc.RootElement.TryGetProperty("issuer", out var iss) ? iss.GetString() : null;
        }
        catch
        {
            return null;
        }
    }
}
