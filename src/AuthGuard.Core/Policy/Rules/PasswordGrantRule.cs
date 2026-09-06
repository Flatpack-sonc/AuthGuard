using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class PasswordGrantRule : IPolicyRule
{
    public string RuleId => "AG-GRANT-001";

    private static readonly HashSet<string> LegacyGrants = new(StringComparer.OrdinalIgnoreCase)
    {
        "password",
        "http://auth0.com/oauth/grant-type/password-realm"
    };

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        var grants = context.Configuration.GrantTypesSupported;
        if (grants is null)
        {
            yield break;
        }

        var legacy = grants.Where(g => LegacyGrants.Contains(g) ||
                                       g.Contains("password", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (legacy.Count > 0)
        {
            yield return new Finding
            {
                Id = "AG-GRANT-001",
                Title = "Resource owner password credentials grant advertised",
                Severity = ProfileSeverity.Escalate(context.Profile, Severity.Critical, Severity.Critical, Severity.High)
                           ?? Severity.Critical,
                Description = "The password grant exposes user credentials to the client and is obsolete for most applications.",
                Evidence = $"grant_types_supported includes: [{string.Join(", ", legacy)}]",
                Remediation = "Remove the password grant. Use authorization code + PKCE, device code, or client credentials as appropriate.",
                References =
                [
                    "https://datatracker.ietf.org/doc/html/rfc9700#section-2.4",
                    "https://oauth.net/2/grant-types/password/"
                ],
                RuleCategory = "Grants"
            };
        }

        if (grants.Any(g => string.Equals(g, "implicit", StringComparison.OrdinalIgnoreCase)))
        {
            yield return new Finding
            {
                Id = "AG-GRANT-002",
                Title = "Implicit grant type advertised",
                Severity = ProfileSeverity.Escalate(context.Profile, Severity.High, Severity.Critical, Severity.Medium)
                           ?? Severity.High,
                Description = "grant_types_supported lists 'implicit', which is no longer recommended.",
                Evidence = $"grant_types_supported=[{string.Join(", ", grants)}]",
                Remediation = "Remove implicit from grant_types_supported and migrate clients to authorization code + PKCE.",
                References =
                [
                    "https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.2"
                ],
                RuleCategory = "Grants"
            };
        }
    }
}
