using AuthGuard.Core.Discovery;
using AuthGuard.Core.Models;
using AuthGuard.Core.Policy;
using AuthGuard.Core.Scoring;
using AuthGuard.Core.Suppressions;

namespace AuthGuard.Core;

/// <summary>Orchestrates discovery, policy evaluation, IdP adjust, suppressions, and scoring.</summary>
public sealed class AuditService
{
    private readonly DiscoveryClient _discoveryClient;
    private readonly PolicyEngine _policyEngine;

    public AuditService(DiscoveryClient? discoveryClient = null, PolicyEngine? policyEngine = null)
    {
        _discoveryClient = discoveryClient ?? new DiscoveryClient();
        _policyEngine = policyEngine ?? new PolicyEngine();
    }

    public async Task<AuditResult> AuditAsync(AuditOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        DiscoveryFetchResult fetch;
        var isOffline = !string.IsNullOrWhiteSpace(options.OfflineConfigPath);

        if (isOffline)
        {
            fetch = DiscoveryClient.LoadOffline(options.OfflineConfigPath!, options.OfflineJwksPath);
        }
        else
        {
            if (string.IsNullOrWhiteSpace(options.IssuerUrl))
            {
                throw new ArgumentException("IssuerUrl is required unless OfflineConfigPath is set.", nameof(options));
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(options.Timeout);
            fetch = await _discoveryClient.FetchAsync(options.IssuerUrl, options.FetchJwks, cts.Token)
                .ConfigureAwait(false);
        }

        var requested = options.IssuerUrl
                        ?? fetch.Configuration?.Issuer
                        ?? "unknown";

        if (!fetch.Success || fetch.Configuration is null)
        {
            var failureFindings = new List<Finding>();
            var diagnostics = fetch.Diagnostics;
            var stubConfig = new OpenIdConfiguration { Issuer = requested };
            var failContext = new AuditContext
            {
                RequestedIssuer = requested,
                Configuration = stubConfig,
                Profile = options.Profile,
                Idp = options.Idp,
                Diagnostics = diagnostics,
                IsOffline = isOffline
            };
            failureFindings.AddRange(_policyEngine.Evaluate(failContext));

            if (failureFindings.Count == 0)
            {
                failureFindings.Add(new Finding
                {
                    Id = "AG-DISC-001",
                    Title = "OIDC discovery document unavailable",
                    Severity = Severity.Critical,
                    Description = "Discovery failed without detailed diagnostics.",
                    Evidence = diagnostics.HttpError ?? diagnostics.TlsError ?? "unknown error",
                    Remediation = "Verify the issuer URL and network connectivity.",
                    References = ["https://openid.net/specs/openid-connect-discovery-1_0.html"],
                    RuleCategory = "Discovery"
                });
            }

            return Finalize(
                requested,
                options,
                failureFindings,
                fetch.Source,
                configuration: null);
        }

        var context = new AuditContext
        {
            RequestedIssuer = DiscoveryDocumentParser.NormalizeIssuerUrl(
                options.IssuerUrl ?? fetch.Configuration.Issuer ?? requested),
            Configuration = fetch.Configuration,
            Jwks = fetch.Jwks,
            Profile = options.Profile,
            Idp = options.Idp,
            Diagnostics = fetch.Diagnostics,
            IsOffline = isOffline
        };

        var raw = _policyEngine.Evaluate(context);
        return Finalize(
            fetch.Configuration.Issuer
            ?? DiscoveryDocumentParser.NormalizeIssuerUrl(options.IssuerUrl ?? requested),
            options,
            raw,
            fetch.Source,
            fetch.Configuration);
    }

    private static AuditResult Finalize(
        string issuer,
        AuditOptions options,
        IReadOnlyList<Finding> rawFindings,
        string? discoverySource,
        OpenIdConfiguration? configuration)
    {
        var adjusted = IdpPresetAdjuster.Apply(rawFindings, options.Idp);
        var applied = SuppressionEngine.Apply(adjusted, options.Suppressions, options.Baseline);
        var (score, grade, counts) = ScoreCalculator.Evaluate(applied.Active);

        return new AuditResult
        {
            Issuer = issuer,
            AuditedAt = DateTimeOffset.UtcNow,
            Profile = options.Profile,
            Idp = options.Idp,
            Findings = applied.Active,
            SuppressedFindings = applied.Suppressed,
            ExpiredSuppressions = applied.ExpiredRules,
            ManualChecklist = PolicyEngine.BuildManualChecklist(),
            Score = score,
            Grade = grade,
            Counts = counts,
            DiscoverySource = discoverySource,
            Configuration = configuration,
            PolicyFilePath = options.PolicyFilePath,
            BaselinePath = options.BaselinePath,
            ToolVersion = "1.1.0"
        };
    }
}
