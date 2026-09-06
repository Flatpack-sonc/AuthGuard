using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class PkceRule : IPolicyRule
{
    public string RuleId => "AG-PKCE-001";

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        var methods = context.Configuration.CodeChallengeMethodsSupported;
        var grants = context.Configuration.GrantTypesSupported
                     ?? ["authorization_code"];

        var usesAuthCode = grants.Any(g =>
            string.Equals(g, "authorization_code", StringComparison.OrdinalIgnoreCase));

        if (!usesAuthCode && context.Profile == PolicyProfile.Relaxed)
        {
            yield break;
        }

        if (methods is null || methods.Count == 0)
        {
            var severity = ProfileSeverity.Escalate(context.Profile, Severity.High, Severity.Critical, Severity.Medium)
                           ?? Severity.High;
            yield return new Finding
            {
                Id = "AG-PKCE-001",
                Title = "PKCE not advertised",
                Severity = severity,
                Description = "code_challenge_methods_supported is missing. Modern OAuth best practice requires PKCE for authorization code flows (public and confidential clients).",
                Evidence = "code_challenge_methods_supported is absent or empty",
                Remediation = "Advertise and enforce PKCE. At minimum support S256 (RFC 7636). Prefer requiring PKCE for all authorization code clients.",
                References =
                [
                    "https://datatracker.ietf.org/doc/html/rfc7636",
                    "https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Authorization_Server_Weaknesses"
                ],
                RuleCategory = "PKCE"
            };
            yield break;
        }

        var hasS256 = methods.Any(m => string.Equals(m, "S256", StringComparison.OrdinalIgnoreCase));
        if (!hasS256)
        {
            yield return new Finding
            {
                Id = "AG-PKCE-002",
                Title = "PKCE S256 not supported",
                Severity = ProfileSeverity.Escalate(context.Profile, Severity.High, Severity.Critical, Severity.Medium)
                           ?? Severity.High,
                Description = "PKCE is advertised but S256 is missing. plain is weak and should not be the only option.",
                Evidence = $"code_challenge_methods_supported=[{string.Join(", ", methods)}]",
                Remediation = "Add S256 to code_challenge_methods_supported and prefer rejecting 'plain' for new clients.",
                References =
                [
                    "https://datatracker.ietf.org/doc/html/rfc7636#section-4.2",
                    "https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1"
                ],
                RuleCategory = "PKCE"
            };
        }

        var hasPlain = methods.Any(m => string.Equals(m, "plain", StringComparison.OrdinalIgnoreCase));
        if (hasPlain && context.Profile == PolicyProfile.Strict)
        {
            yield return new Finding
            {
                Id = "AG-PKCE-003",
                Title = "PKCE 'plain' method advertised",
                Severity = Severity.Medium,
                Description = "The 'plain' code challenge method provides limited protection compared to S256.",
                Evidence = $"code_challenge_methods_supported=[{string.Join(", ", methods)}]",
                Remediation = "Disable 'plain' for new clients; require S256 only.",
                References =
                [
                    "https://datatracker.ietf.org/doc/html/rfc7636#section-4.2"
                ],
                RuleCategory = "PKCE"
            };
        }
    }
}
