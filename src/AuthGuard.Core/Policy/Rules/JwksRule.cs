using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class JwksRule : IPolicyRule
{
    public string RuleId => "AG-JWKS-002";

    private static readonly HashSet<string> KnownKty = new(StringComparer.OrdinalIgnoreCase)
    {
        "RSA", "EC", "OKP", "oct"
    };

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        if (string.IsNullOrWhiteSpace(context.Configuration.JwksUri))
        {
            yield return new Finding
            {
                Id = "AG-JWKS-002",
                Title = "jwks_uri missing",
                Severity = Severity.Critical,
                Description = "OIDC discovery must advertise jwks_uri so relying parties can obtain signature verification keys.",
                Evidence = "jwks_uri is absent",
                Remediation = "Publish a JWKS document at an HTTPS URL and set jwks_uri in the discovery document.",
                References =
                [
                    "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata",
                    "https://datatracker.ietf.org/doc/html/rfc7517"
                ],
                RuleCategory = "JWKS"
            };
            yield break;
        }

        var jwks = context.Jwks;
        if (jwks is null)
        {
            // Fetch failure already reported by DiscoveryHealthRule when diagnostics present.
            yield break;
        }

        if (jwks.Keys is null || jwks.Keys.Count == 0)
        {
            yield return new Finding
            {
                Id = "AG-JWKS-003",
                Title = "JWKS contains no keys",
                Severity = Severity.Critical,
                Description = "The JWK Set is empty. Clients cannot validate token signatures.",
                Evidence = "keys=[]",
                Remediation = "Publish at least one active signing key (RSA/EC) with kid, and plan for key rotation.",
                References =
                [
                    "https://datatracker.ietf.org/doc/html/rfc7517#section-5"
                ],
                RuleCategory = "JWKS"
            };
            yield break;
        }

        foreach (var key in jwks.Keys)
        {
            if (string.IsNullOrWhiteSpace(key.Kty))
            {
                yield return new Finding
                {
                    Id = "AG-JWKS-004",
                    Title = "JWK missing kty",
                    Severity = Severity.High,
                    Description = "A JWK entry is missing the required 'kty' parameter.",
                    Evidence = $"kid={key.Kid ?? "(none)"}",
                    Remediation = "Ensure every JWK includes kty and the parameters required for that key type.",
                    References = ["https://datatracker.ietf.org/doc/html/rfc7517#section-4.1"],
                    RuleCategory = "JWKS"
                };
                continue;
            }

            if (!KnownKty.Contains(key.Kty))
            {
                yield return new Finding
                {
                    Id = "AG-JWKS-005",
                    Title = "Unusual JWK key type",
                    Severity = Severity.Medium,
                    Description = $"JWK uses uncommon kty '{key.Kty}'. Verify this is intentional and supported by your RPs.",
                    Evidence = $"kty={key.Kty}, kid={key.Kid ?? "(none)"}",
                    Remediation = "Prefer RSA or EC keys for ID token signatures unless you have a documented need for another type.",
                    References = ["https://datatracker.ietf.org/doc/html/rfc7517#section-4.1"],
                    RuleCategory = "JWKS"
                };
            }

            if (string.Equals(key.Kty, "oct", StringComparison.OrdinalIgnoreCase))
            {
                yield return new Finding
                {
                    Id = "AG-JWKS-006",
                    Title = "Symmetric (oct) key published in JWKS",
                    Severity = Severity.Critical,
                    Description = "Publishing symmetric keys in a public JWKS is a severe configuration mistake and may expose shared secrets.",
                    Evidence = $"kty=oct, kid={key.Kid ?? "(none)"}",
                    Remediation = "Never publish symmetric keys in a public JWKS. Use asymmetric signing keys only.",
                    References =
                    [
                        "https://datatracker.ietf.org/doc/html/rfc7517",
                        "https://datatracker.ietf.org/doc/html/rfc8725"
                    ],
                    RuleCategory = "JWKS"
                };
            }

            if (string.IsNullOrWhiteSpace(key.Kid) && context.Profile != PolicyProfile.Relaxed)
            {
                yield return new Finding
                {
                    Id = "AG-JWKS-007",
                    Title = "JWK missing kid",
                    Severity = Severity.Low,
                    Description = "Keys without kid complicate rotation and key selection for JWT validation.",
                    Evidence = $"kty={key.Kty}, alg={key.Alg ?? "(none)"}",
                    Remediation = "Assign a stable kid to each signing key and include kid in JWT headers.",
                    References = ["https://datatracker.ietf.org/doc/html/rfc7517#section-4.5"],
                    RuleCategory = "JWKS"
                };
            }
        }
    }
}
