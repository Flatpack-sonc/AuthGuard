using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class HttpsIssuerRule : IPolicyRule
{
    public string RuleId => "AG-TLS-002";

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        var issuer = context.Configuration.Issuer ?? context.RequestedIssuer;
        var auth = context.Configuration.AuthorizationEndpoint;
        var token = context.Configuration.TokenEndpoint;
        var jwks = context.Configuration.JwksUri;

        if (IsHttp(issuer) || IsHttp(context.RequestedIssuer))
        {
            yield return new Finding
            {
                Id = "AG-TLS-002",
                Title = "Issuer uses HTTP instead of HTTPS",
                Severity = Severity.Critical,
                Description = "OIDC issuers must be served over HTTPS. An HTTP issuer enables metadata and token interception.",
                Evidence = $"issuer='{issuer}', requested='{context.RequestedIssuer}'",
                Remediation = "Serve the authorization server exclusively over HTTPS and advertise an https:// issuer identifier.",
                References =
                [
                    "https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery",
                    "https://datatracker.ietf.org/doc/html/rfc8414#section-2"
                ],
                RuleCategory = "Transport"
            };
        }

        foreach (var (name, url) in new[]
                 {
                     ("authorization_endpoint", auth),
                     ("token_endpoint", token),
                     ("jwks_uri", jwks)
                 })
        {
            if (IsHttp(url))
            {
                yield return new Finding
                {
                    Id = "AG-TLS-003",
                    Title = $"Endpoint '{name}' is not HTTPS",
                    Severity = Severity.High,
                    Description = $"Critical OAuth/OIDC endpoint '{name}' is advertised over HTTP, which violates transport security best practices.",
                    Evidence = $"{name}={url}",
                    Remediation = $"Advertise and serve '{name}' exclusively over HTTPS.",
                    References =
                    [
                        "https://datatracker.ietf.org/doc/html/rfc6749#section-3.1",
                        "https://owasp.org/www-project-api-security/"
                    ],
                    RuleCategory = "Transport"
                };
            }
        }
    }

    private static bool IsHttp(string? url) =>
        !string.IsNullOrWhiteSpace(url)
        && url.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
}
