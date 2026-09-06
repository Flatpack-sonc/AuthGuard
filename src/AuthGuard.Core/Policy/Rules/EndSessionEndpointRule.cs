using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy.Rules;

public sealed class EndSessionEndpointRule : IPolicyRule
{
    public string RuleId => "AG-LOGOUT-001";

    public IEnumerable<Finding> Evaluate(AuditContext context)
    {
        var cfg = context.Configuration;
        var hasEndSession = !string.IsNullOrWhiteSpace(cfg.EndSessionEndpoint);
        var hasFront = cfg.FrontchannelLogoutSupported == true;
        var hasBack = cfg.BackchannelLogoutSupported == true;

        if (hasEndSession || hasFront || hasBack)
        {
            yield break;
        }

        var severity = context.Profile switch
        {
            PolicyProfile.Strict => Severity.Low,
            PolicyProfile.Relaxed => Severity.Info,
            _ => Severity.Low
        };

        yield return new Finding
        {
            Id = "AG-LOGOUT-001",
            Title = "No RP-Initiated Logout / logout endpoints advertised",
            Severity = severity,
            Description = "Discovery does not advertise end_session_endpoint or front/back-channel logout support, which complicates single logout.",
            Evidence = "end_session_endpoint absent; frontchannel_logout_supported/backchannel_logout_supported not true",
            Remediation = "Implement OpenID Connect RP-Initiated Logout and/or front/back-channel logout, and advertise the corresponding metadata.",
            References =
            [
                "https://openid.net/specs/openid-connect-rpinitiated-1_0.html",
                "https://openid.net/specs/openid-connect-frontchannel-1_0.html",
                "https://openid.net/specs/openid-connect-backchannel-1_0.html"
            ],
            RuleCategory = "Logout"
        };
    }
}
