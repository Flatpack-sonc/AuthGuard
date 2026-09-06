using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class RequiredEndpointsRule : IPolicyRule
{
    public string RuleId => "AG-EP-001";

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        var cfg = context.Configuration;

        if (string.IsNullOrWhiteSpace(cfg.AuthorizationEndpoint))
        {
            yield return new Finding
            {
                Id = "AG-EP-001",
                Title = "authorization_endpoint missing",
                Severity = Severity.Critical,
                Description = "OIDC discovery must include authorization_endpoint for interactive flows.",
                Evidence = "authorization_endpoint is absent",
                Remediation = "Advertise the HTTPS authorization endpoint in the discovery document.",
                References =
                [
                    "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata"
                ],
                RuleCategory = "Endpoints"
            };
        }

        if (string.IsNullOrWhiteSpace(cfg.TokenEndpoint))
        {
            yield return new Finding
            {
                Id = "AG-EP-002",
                Title = "token_endpoint missing",
                Severity = Severity.Critical,
                Description = "OIDC discovery must include token_endpoint for code exchange and client credentials.",
                Evidence = "token_endpoint is absent",
                Remediation = "Advertise the HTTPS token endpoint in the discovery document.",
                References =
                [
                    "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata"
                ],
                RuleCategory = "Endpoints"
            };
        }
    }
}
