using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class TokenEndpointAuthRule : IPolicyRule
{
    public string RuleId => "AG-TEA-001";

    private static readonly HashSet<string> StrongMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "private_key_jwt",
        "client_secret_jwt",
        "tls_client_auth",
        "self_signed_tls_client_auth"
    };

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        var methods = context.Configuration.TokenEndpointAuthMethodsSupported;
        if (methods is null || methods.Count == 0)
        {
            if (context.Profile != PolicyProfile.Relaxed)
            {
                yield return new Finding
                {
                    Id = "AG-TEA-001",
                    Title = "token_endpoint_auth_methods_supported missing",
                    Severity = ProfileSeverity.Escalate(context.Profile, Severity.Medium, Severity.High, Severity.Low)
                               ?? Severity.Medium,
                    Description = "Discovery does not advertise token endpoint authentication methods, so client auth strength cannot be assessed from metadata.",
                    Evidence = "token_endpoint_auth_methods_supported is absent or empty",
                    Remediation = "Advertise supported methods and prefer private_key_jwt or mTLS for confidential clients. Avoid none except for public clients.",
                    References =
                    [
                        "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata",
                        "https://datatracker.ietf.org/doc/html/rfc7523"
                    ],
                    RuleCategory = "ClientAuth"
                };
            }

            yield break;
        }

        var onlyNone = methods.All(m => string.Equals(m, "none", StringComparison.OrdinalIgnoreCase));
        if (onlyNone)
        {
            yield return new Finding
            {
                Id = "AG-TEA-002",
                Title = "Only 'none' token endpoint auth method supported",
                Severity = ProfileSeverity.Escalate(context.Profile, Severity.High, Severity.Critical, Severity.Medium)
                           ?? Severity.High,
                Description = "If the only advertised method is 'none', confidential clients cannot authenticate at the token endpoint.",
                Evidence = $"token_endpoint_auth_methods_supported=[{string.Join(", ", methods)}]",
                Remediation = "Support client_secret_basic/post at minimum for confidential clients; prefer private_key_jwt or tls_client_auth.",
                References =
                [
                    "https://datatracker.ietf.org/doc/html/rfc6749#section-2.3",
                    "https://datatracker.ietf.org/doc/html/rfc7523"
                ],
                RuleCategory = "ClientAuth"
            };
        }

        var hasStrong = methods.Any(m => StrongMethods.Contains(m));
        var hasSecretBasic = methods.Any(m =>
            string.Equals(m, "client_secret_basic", StringComparison.OrdinalIgnoreCase)
            || string.Equals(m, "client_secret_post", StringComparison.OrdinalIgnoreCase));

        if (!hasStrong && hasSecretBasic && context.Profile == PolicyProfile.Strict)
        {
            yield return new Finding
            {
                Id = "AG-TEA-003",
                Title = "No asymmetric/mTLS client authentication methods",
                Severity = Severity.Low,
                Description = "Only shared-secret client authentication methods are advertised. Strict profiles prefer private_key_jwt or mTLS.",
                Evidence = $"token_endpoint_auth_methods_supported=[{string.Join(", ", methods)}]",
                Remediation = "Add private_key_jwt and/or tls_client_auth for high-assurance confidential clients.",
                References =
                [
                    "https://datatracker.ietf.org/doc/html/rfc7523",
                    "https://datatracker.ietf.org/doc/html/rfc8705"
                ],
                RuleCategory = "ClientAuth"
            };
        }
    }
}
