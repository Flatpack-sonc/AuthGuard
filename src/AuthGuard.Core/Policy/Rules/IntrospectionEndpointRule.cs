using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class IntrospectionEndpointRule : IPolicyRule
{
    public string RuleId => "AG-INT-001";

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        if (!string.IsNullOrWhiteSpace(context.Configuration.IntrospectionEndpoint))
        {
            yield break;
        }

        var severity = context.Profile switch
        {
            PolicyProfile.Strict => Severity.Medium,
            PolicyProfile.Relaxed => Severity.Info,
            _ => Severity.Low
        };

        yield return new Finding
        {
            Id = "AG-INT-001",
            Title = "introspection_endpoint not advertised",
            Severity = severity,
            Description = "Resource servers that need opaque token validation benefit from RFC 7662 introspection. Absence may be acceptable for JWT-only deployments.",
            Evidence = "introspection_endpoint is absent",
            Remediation = "If you issue opaque tokens, implement and advertise introspection_endpoint. For JWT access tokens, document that introspection is intentionally unused.",
            References =
            [
                "https://datatracker.ietf.org/doc/html/rfc7662"
            ],
            RuleCategory = "Lifecycle"
        };
    }
}
