using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class RevocationEndpointRule : IPolicyRule
{
    public string RuleId => "AG-REV-001";

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        if (!string.IsNullOrWhiteSpace(context.Configuration.RevocationEndpoint))
        {
            yield break;
        }

        var severity = context.Profile switch
        {
            PolicyProfile.Strict => Severity.Medium,
            PolicyProfile.Relaxed => Severity.Info,
            _ => Severity.Medium
        };

        yield return new Finding
        {
            Id = "AG-REV-001",
            Title = "revocation_endpoint not advertised",
            Severity = severity,
            Description = "Without a revocation endpoint, clients cannot reliably invalidate refresh/access tokens on logout or compromise.",
            Evidence = "revocation_endpoint is absent",
            Remediation = "Implement RFC 7009 token revocation and advertise revocation_endpoint in discovery.",
            References =
            [
                "https://datatracker.ietf.org/doc/html/rfc7009",
                "https://datatracker.ietf.org/doc/html/rfc8414"
            ],
            RuleCategory = "Lifecycle"
        };
    }
}
