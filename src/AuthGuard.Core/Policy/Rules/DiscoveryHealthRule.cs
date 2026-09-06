using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class DiscoveryHealthRule : IPolicyRule
{
    public string RuleId => "AG-DISC-001";

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        var d = context.Diagnostics;
        if (d is null)
        {
            yield break;
        }

        if (!string.IsNullOrWhiteSpace(d.TlsError))
        {
            yield return new Finding
            {
                Id = "AG-TLS-001",
                Title = "TLS error while fetching discovery",
                Severity = Severity.Critical,
                Description = "The OIDC discovery endpoint could not be fetched over a trustworthy TLS connection. Issuers must present a valid certificate chain.",
                Evidence = d.TlsError!,
                Remediation = "Fix TLS certificate configuration on the authorization server (valid chain, hostname match, modern protocols). Do not disable certificate validation in production clients.",
                References =
                [
                    "https://datatracker.ietf.org/doc/html/rfc6125",
                    "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning"
                ],
                RuleCategory = "Transport"
            };
        }

        if (!string.IsNullOrWhiteSpace(d.HttpError) && !d.DiscoverySucceeded)
        {
            yield return new Finding
            {
                Id = "AG-DISC-001",
                Title = "OIDC discovery document unavailable",
                Severity = Severity.Critical,
                Description = "AuthGuard could not retrieve or parse the OpenID Provider Metadata document. Without discovery, clients cannot safely configure endpoints.",
                Evidence = d.HttpError! + (d.StatusCode is int code ? $" (status {code})" : string.Empty),
                Remediation = "Ensure /.well-known/openid-configuration is publicly reachable over HTTPS and returns valid JSON metadata.",
                References =
                [
                    "https://openid.net/specs/openid-connect-discovery-1_0.html"
                ],
                RuleCategory = "Discovery"
            };
        }

        if (!string.IsNullOrWhiteSpace(d.JwksHttpError))
        {
            var severity = ProfileSeverity.Escalate(context.Profile, Severity.High, Severity.Critical, Severity.Medium)
                           ?? Severity.High;
            yield return new Finding
            {
                Id = "AG-JWKS-001",
                Title = "JWKS endpoint fetch failed",
                Severity = severity,
                Description = "The jwks_uri advertised in discovery could not be retrieved. Relying parties need JWKS to validate ID/access token signatures.",
                Evidence = d.JwksHttpError! + (d.JwksStatusCode is int jc ? $" (status {jc})" : string.Empty),
                Remediation = "Ensure jwks_uri is correct, reachable over HTTPS, and returns a valid JWK Set.",
                References =
                [
                    "https://datatracker.ietf.org/doc/html/rfc7517",
                    "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata"
                ],
                RuleCategory = "JWKS"
            };
        }
    }
}
