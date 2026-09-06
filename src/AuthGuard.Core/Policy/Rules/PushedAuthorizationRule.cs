using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class PushedAuthorizationRule : IPolicyRule
{
    public string RuleId => "AG-PAR-001";

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        if (context.Profile != PolicyProfile.Strict)
        {
            yield break;
        }

        if (!string.IsNullOrWhiteSpace(context.Configuration.PushedAuthorizationRequestEndpoint))
        {
            yield break;
        }

        yield return new Finding
        {
            Id = "AG-PAR-001",
            Title = "Pushed Authorization Requests (PAR) not advertised",
            Severity = Severity.Info,
            Description = "PAR (RFC 9126) reduces front-channel parameter exposure. Strict profile notes when it is not available.",
            Evidence = "pushed_authorization_request_endpoint is absent",
            Remediation = "Consider implementing PAR for high-security deployments and advertising pushed_authorization_request_endpoint.",
            References =
            [
                "https://datatracker.ietf.org/doc/html/rfc9126",
                "https://datatracker.ietf.org/doc/html/rfc9700"
            ],
            RuleCategory = "PAR"
        };
    }
}
