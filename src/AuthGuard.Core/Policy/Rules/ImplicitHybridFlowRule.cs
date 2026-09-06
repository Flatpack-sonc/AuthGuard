using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class ImplicitHybridFlowRule : IPolicyRule
{
    public string RuleId => "AG-FLOW-001";

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        var responseTypes = context.Configuration.ResponseTypesSupported;
        if (responseTypes is null || responseTypes.Count == 0)
        {
            if (context.Profile == PolicyProfile.Strict)
            {
                yield return new Finding
                {
                    Id = "AG-FLOW-000",
                    Title = "response_types_supported not advertised",
                    Severity = Severity.Low,
                    Description = "Discovery does not list response_types_supported, so AuthGuard cannot verify that implicit/hybrid flows are disabled.",
                    Evidence = "response_types_supported is absent",
                    Remediation = "Advertise supported response types and exclude token / id_token-only and hybrid combinations for new applications.",
                    References =
                    [
                        "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata"
                    ],
                    RuleCategory = "Flows"
                };
            }

            yield break;
        }

        var implicitOrHybrid = responseTypes
            .Where(rt =>
            {
                var parts = rt.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                // token anywhere, or id_token without code (implicit), or hybrid (code + token/id_token)
                var hasToken = parts.Any(p => string.Equals(p, "token", StringComparison.OrdinalIgnoreCase));
                var hasIdToken = parts.Any(p => string.Equals(p, "id_token", StringComparison.OrdinalIgnoreCase));
                var hasCode = parts.Any(p => string.Equals(p, "code", StringComparison.OrdinalIgnoreCase));
                return hasToken || (hasIdToken && !hasCode) || (hasCode && (hasToken || hasIdToken));
            })
            .ToList();

        if (implicitOrHybrid.Count == 0)
        {
            yield break;
        }

        var severity = ProfileSeverity.Escalate(context.Profile, Severity.High, Severity.Critical, Severity.Medium)
                       ?? Severity.High;

        yield return new Finding
        {
            Id = "AG-FLOW-001",
            Title = "Implicit or hybrid response types advertised",
            Severity = severity,
            Description = "Response types that return tokens in the front channel (implicit/hybrid) are discouraged. Prefer authorization code + PKCE.",
            Evidence = $"response_types_supported includes: [{string.Join(", ", implicitOrHybrid)}]",
            Remediation = "Disable implicit and hybrid flows for new clients. Prefer response_type=code with PKCE. Keep legacy types only with documented exceptions.",
            References =
            [
                "https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.2",
                "https://oauth.net/2/grant-types/implicit/",
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Authorization_Server_Weaknesses"
            ],
            RuleCategory = "Flows"
        };
    }
}
