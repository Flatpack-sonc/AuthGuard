using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class ClaimsScopesHygieneRule : IPolicyRule
{
    public string RuleId => "AG-SCOPE-001";

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        if (context.Profile == PolicyProfile.Relaxed)
        {
            yield break;
        }

        var scopes = context.Configuration.ScopesSupported;
        var claims = context.Configuration.ClaimsSupported;

        if (scopes is null || scopes.Count == 0)
        {
            yield return new Finding
            {
                Id = "AG-SCOPE-001",
                Title = "scopes_supported not advertised",
                Severity = Severity.Info,
                Description = "Listing scopes_supported helps clients discover available permissions and avoid guessing scope names.",
                Evidence = "scopes_supported is absent or empty",
                Remediation = "Advertise the scopes your OP supports, including openid for OIDC.",
                References =
                [
                    "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata"
                ],
                RuleCategory = "Hygiene"
            };
        }
        else if (!scopes.Any(s => string.Equals(s, "openid", StringComparison.OrdinalIgnoreCase)))
        {
            yield return new Finding
            {
                Id = "AG-SCOPE-002",
                Title = "openid scope not listed in scopes_supported",
                Severity = Severity.Low,
                Description = "OIDC providers should include the openid scope in scopes_supported.",
                Evidence = $"scopes_supported=[{string.Join(", ", scopes)}]",
                Remediation = "Include 'openid' in scopes_supported when offering OpenID Connect.",
                References =
                [
                    "https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest"
                ],
                RuleCategory = "Hygiene"
            };
        }

        if (claims is null || claims.Count == 0)
        {
            yield return new Finding
            {
                Id = "AG-CLAIM-001",
                Title = "claims_supported not advertised",
                Severity = Severity.Info,
                Description = "Advertising claims_supported improves client interoperability and makes the identity claim surface explicit for review.",
                Evidence = "claims_supported is absent or empty",
                Remediation = "List standard claims your OP may return (sub, iss, etc.) in claims_supported.",
                References =
                [
                    "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata"
                ],
                RuleCategory = "Hygiene"
            };
        }
    }
}
