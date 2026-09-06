using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class IssuerIdentificationRule : IPolicyRule
{
    public string RuleId => "AG-ISS-001";

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        var cfg = context.Configuration;

        if (string.IsNullOrWhiteSpace(cfg.Issuer))
        {
            yield return new Finding
            {
                Id = "AG-ISS-001",
                Title = "issuer claim missing from discovery",
                Severity = Severity.High,
                Description = "OpenID Provider Metadata must include an issuer identifier used by clients for issuer validation.",
                Evidence = "issuer field is null or empty",
                Remediation = "Set issuer to the canonical HTTPS issuer URL (no query/fragment) matching token iss claims.",
                References =
                [
                    "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata",
                    "https://openid.net/specs/openid-connect-core-1_0.html#IDToken"
                ],
                RuleCategory = "Issuer"
            };
        }
        else if (!context.IsOffline
                 && !string.IsNullOrWhiteSpace(context.RequestedIssuer)
                 && !IssuersMatch(cfg.Issuer, context.RequestedIssuer))
        {
            yield return new Finding
            {
                Id = "AG-ISS-002",
                Title = "Discovered issuer mismatches requested URL",
                Severity = Severity.Medium,
                Description = "The issuer in metadata does not match the requested issuer URL. Clients should use the discovered issuer for validation.",
                Evidence = $"requested='{context.RequestedIssuer}', discovery.issuer='{cfg.Issuer}'",
                Remediation = "Confirm you are pointing AuthGuard at the correct issuer. Clients must validate iss against the discovered issuer value.",
                References =
                [
                    "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig"
                ],
                RuleCategory = "Issuer"
            };
        }

        if (cfg.AuthorizationResponseIssParameterSupported != true)
        {
            var severity = context.Profile switch
            {
                PolicyProfile.Strict => Severity.Medium,
                PolicyProfile.Relaxed => Severity.Info,
                _ => Severity.Low
            };

            if (severity == Severity.Info && !ProfileSeverity.IncludeInfo(context.Profile))
            {
                yield break;
            }

            yield return new Finding
            {
                Id = "AG-ISS-003",
                Title = "authorization_response_iss_parameter_supported not enabled",
                Severity = severity,
                Description = "RFC 9207 iss authorization response parameter helps clients detect mix-up attacks when multiple IdPs are used.",
                Evidence = $"authorization_response_iss_parameter_supported={cfg.AuthorizationResponseIssParameterSupported?.ToString() ?? "absent"}",
                Remediation = "Support and return the iss parameter in authorization responses (RFC 9207).",
                References =
                [
                    "https://datatracker.ietf.org/doc/html/rfc9207",
                    "https://datatracker.ietf.org/doc/html/rfc9700#section-2.1"
                ],
                RuleCategory = "Issuer"
            };
        }
    }

    private static bool IssuersMatch(string discovered, string requested)
    {
        static string Norm(string s)
        {
            s = s.Trim().TrimEnd('/');
            if (s.EndsWith("/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase))
            {
                s = s[..^"/.well-known/openid-configuration".Length];
            }

            return s;
        }

        return string.Equals(Norm(discovered), Norm(requested), StringComparison.OrdinalIgnoreCase);
    }
}
