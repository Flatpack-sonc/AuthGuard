using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class WeakSigningAlgorithmsRule : IPolicyRule
{
    public string RuleId => "AG-ALG-001";

    private static readonly HashSet<string> WeakAlgs = new(StringComparer.OrdinalIgnoreCase)
    {
        "none",
        "HS256",
        "HS384",
        "HS512",
        "RS1",
        "PS1"
    };

    private static readonly HashSet<string> SymmetricAlgs = new(StringComparer.OrdinalIgnoreCase)
    {
        "HS256",
        "HS384",
        "HS512"
    };

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        var algs = context.Configuration.IdTokenSigningAlgValuesSupported;
        if (algs is null || algs.Count == 0)
        {
            if (context.Profile != PolicyProfile.Relaxed)
            {
                yield return new Finding
                {
                    Id = "AG-ALG-001",
                    Title = "id_token_signing_alg_values_supported missing",
                    Severity = Severity.Medium,
                    Description = "Discovery does not list ID token signing algorithms. Clients cannot confirm that 'none' or weak algorithms are rejected.",
                    Evidence = "id_token_signing_alg_values_supported is absent or empty",
                    Remediation = "Advertise asymmetric algorithms such as RS256, ES256, or PS256. Never support 'none' for ID tokens in production.",
                    References =
                    [
                        "https://openid.net/specs/openid-connect-core-1_0.html#SignedIDToken",
                        "https://datatracker.ietf.org/doc/html/rfc7518"
                    ],
                    RuleCategory = "Algorithms"
                };
            }

            yield break;
        }

        if (algs.Any(a => string.Equals(a, "none", StringComparison.OrdinalIgnoreCase)))
        {
            yield return new Finding
            {
                Id = "AG-ALG-002",
                Title = "ID token signing algorithm 'none' advertised",
                Severity = Severity.Critical,
                Description = "Advertising alg=none for ID tokens violates OIDC security expectations and indicates a dangerous configuration surface.",
                Evidence = $"id_token_signing_alg_values_supported=[{string.Join(", ", algs)}]",
                Remediation = "Remove 'none' from supported ID token signing algorithms. Require asymmetric signatures.",
                References =
                [
                    "https://openid.net/specs/openid-connect-core-1_0.html#IDToken",
                    "https://owasp.org/www-chapter-london/assets/slides/OWASPLondon20171130_JSON_Web_Token.pdf"
                ],
                RuleCategory = "Algorithms"
            };
        }

        var weak = algs.Where(a => WeakAlgs.Contains(a) && !string.Equals(a, "none", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (weak.Count > 0)
        {
            var severity = weak.Any(SymmetricAlgs.Contains)
                ? (ProfileSeverity.Escalate(context.Profile, Severity.High, Severity.Critical, Severity.Medium) ?? Severity.High)
                : Severity.Medium;

            yield return new Finding
            {
                Id = "AG-ALG-003",
                Title = "Weak or symmetric ID token signing algorithms advertised",
                Severity = severity,
                Description = "Symmetric (HS*) algorithms for ID tokens are inappropriate when the RP cannot safely share the OP secret. Prefer asymmetric algorithms.",
                Evidence = $"weak/symmetric algs: [{string.Join(", ", weak)}]",
                Remediation = "Prefer RS256, ES256, or PS256. Avoid HS* for publicly distributed OIDC clients unless a rare, carefully controlled confidential-client design requires it.",
                References =
                [
                    "https://openid.net/specs/openid-connect-core-1_0.html#SignedIDToken",
                    "https://datatracker.ietf.org/doc/html/rfc8725#section-3.2"
                ],
                RuleCategory = "Algorithms"
            };
        }
    }
}
