using AuthGuard.Core.Models;
using AuthGuard.Core.Policy.Rules;

namespace AuthGuard.Core.Policy;

/// <summary>Runs all defensive configuration policy rules.</summary>
public sealed class PolicyEngine
{
    private readonly IReadOnlyList<IPolicyRule> _rules;

    public PolicyEngine(IEnumerable<IPolicyRule>? rules = null)
    {
        _rules = (rules ?? CreateDefaultRules()).ToList();
    }

    public static IReadOnlyList<IPolicyRule> CreateDefaultRules() =>
    [
        new DiscoveryHealthRule(),
        new HttpsIssuerRule(),
        new PkceRule(),
        new ImplicitHybridFlowRule(),
        new PasswordGrantRule(),
        new TokenEndpointAuthRule(),
        new IssuerIdentificationRule(),
        new WeakSigningAlgorithmsRule(),
        new JwksRule(),
        new RevocationEndpointRule(),
        new IntrospectionEndpointRule(),
        new EndSessionEndpointRule(),
        new ClaimsScopesHygieneRule(),
        new PushedAuthorizationRule(),
        new RequiredEndpointsRule()
    ];

    public IReadOnlyList<Finding> Evaluate(AuditContext context)
    {
        return _rules
            .SelectMany(r => r.Evaluate(context))
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Id, StringComparer.Ordinal)
            .ToList();
    }

    public static IReadOnlyList<ManualChecklistItem> BuildManualChecklist() =>
    [
        new ManualChecklistItem
        {
            Id = "AG-MANUAL-001",
            Title = "Refresh token rotation",
            Guidance = "Confirm the authorization server rotates refresh tokens and detects reuse. Discovery metadata does not advertise rotation policy.",
            References =
            [
                "https://datatracker.ietf.org/doc/html/rfc6749#section-6",
                "https://oauth.net/2/refresh-tokens/"
            ]
        },
        new ManualChecklistItem
        {
            Id = "AG-MANUAL-002",
            Title = "Redirect URI allowlist strictness",
            Guidance = "Verify registered redirect URIs are exact-match HTTPS URLs with no wildcards or open redirects.",
            References =
            [
                "https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2",
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include"
            ]
        },
        new ManualChecklistItem
        {
            Id = "AG-MANUAL-003",
            Title = "Access token lifetime and audience binding",
            Guidance = "Review access/ID token TTLs, audience restrictions, and whether tokens are sender-constrained (mTLS/DPoP) for high-risk clients.",
            References =
            [
                "https://datatracker.ietf.org/doc/html/rfc9068",
                "https://datatracker.ietf.org/doc/html/rfc9449"
            ]
        },
        new ManualChecklistItem
        {
            Id = "AG-MANUAL-004",
            Title = "Client authentication secrets hygiene",
            Guidance = "Ensure confidential clients use strong secrets or asymmetric auth (private_key_jwt / mTLS) and secrets are rotated.",
            References =
            [
                "https://datatracker.ietf.org/doc/html/rfc7523",
                "https://owasp.org/www-project-application-security-verification-standard/"
            ]
        },
        new ManualChecklistItem
        {
            Id = "AG-MANUAL-005",
            Title = "Consent and scope minimization",
            Guidance = "Validate that scopes granted to clients follow least privilege and consent screens accurately describe requested claims.",
            References =
            [
                "https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims"
            ]
        }
    ];
}
