using AuthGuard.Core.Discovery;
using AuthGuard.Core.Models;
using AuthGuard.Core.Policy;
using AuthGuard.Core.Policy.Rules;
using FluentAssertions;

namespace AuthGuard.Tests;

public class PolicyRuleTests
{
    private static AuditContext Load(string discovery, string? jwks = null, PolicyProfile profile = PolicyProfile.Standard)
    {
        var config = DiscoveryDocumentParser.ParseConfiguration(FixtureLoader.Read(discovery));
        JsonWebKeySet? keys = jwks is null
            ? null
            : DiscoveryDocumentParser.ParseJwks(FixtureLoader.Read(jwks));

        return new AuditContext
        {
            RequestedIssuer = config.Issuer ?? "https://example.com",
            Configuration = config,
            Jwks = keys,
            Profile = profile,
            Diagnostics = new DiscoveryDiagnostics { UsedHttps = true, DiscoverySucceeded = true },
            IsOffline = true
        };
    }

    [Fact]
    public void GoodConfig_HasNoCriticalOrHigh()
    {
        var engine = new PolicyEngine();
        var findings = engine.Evaluate(Load("good-discovery.json", "good-jwks.json"));
        findings.Where(f => f.Severity >= Severity.High).Should().BeEmpty();
    }

    [Fact]
    public void BadConfig_FlagsPkceMissing()
    {
        var findings = new PkceRule().Evaluate(Load("bad-discovery.json", "bad-jwks.json")).ToList();
        findings.Should().Contain(f => f.Id == "AG-PKCE-001");
    }

    [Fact]
    public void BadConfig_FlagsImplicitHybrid()
    {
        var findings = new ImplicitHybridFlowRule().Evaluate(Load("bad-discovery.json")).ToList();
        findings.Should().Contain(f => f.Id == "AG-FLOW-001");
    }

    [Fact]
    public void BadConfig_FlagsPasswordGrant()
    {
        var findings = new PasswordGrantRule().Evaluate(Load("bad-discovery.json")).ToList();
        findings.Should().Contain(f => f.Id == "AG-GRANT-001");
        findings.Should().Contain(f => f.Id == "AG-GRANT-002");
    }

    [Fact]
    public void BadConfig_FlagsWeakTokenAuth()
    {
        var findings = new TokenEndpointAuthRule().Evaluate(Load("bad-discovery.json")).ToList();
        findings.Should().Contain(f => f.Id == "AG-TEA-002");
    }

    [Fact]
    public void BadConfig_FlagsHttpIssuer()
    {
        var findings = new HttpsIssuerRule().Evaluate(Load("bad-discovery.json")).ToList();
        findings.Should().Contain(f => f.Id == "AG-TLS-002");
        findings.Should().Contain(f => f.Id == "AG-TLS-003");
    }

    [Fact]
    public void BadConfig_FlagsNoneAndHsAlgs()
    {
        var findings = new WeakSigningAlgorithmsRule().Evaluate(Load("bad-discovery.json")).ToList();
        findings.Should().Contain(f => f.Id == "AG-ALG-002");
        findings.Should().Contain(f => f.Id == "AG-ALG-003");
    }

    [Fact]
    public void BadJwks_FlagsOctAndMissingKty()
    {
        var findings = new JwksRule().Evaluate(Load("bad-discovery.json", "bad-jwks.json")).ToList();
        findings.Should().Contain(f => f.Id == "AG-JWKS-006");
        findings.Should().Contain(f => f.Id == "AG-JWKS-004");
    }

    [Fact]
    public void EmptyJwks_FlagsNoKeys()
    {
        var ctx = Load("good-discovery.json", "empty-jwks.json");
        var findings = new JwksRule().Evaluate(ctx).ToList();
        findings.Should().Contain(f => f.Id == "AG-JWKS-003");
    }

    [Fact]
    public void PkcePlainOnly_FlagsMissingS256()
    {
        var findings = new PkceRule().Evaluate(Load("pkce-plain-only.json", "empty-ish-jwks.json")).ToList();
        findings.Should().Contain(f => f.Id == "AG-PKCE-002");
    }

    [Fact]
    public void StrictProfile_FlagsPkcePlain()
    {
        var findings = new PkceRule()
            .Evaluate(Load("pkce-plain-only.json", "empty-ish-jwks.json", PolicyProfile.Strict))
            .ToList();
        findings.Should().Contain(f => f.Id == "AG-PKCE-003");
    }

    [Fact]
    public void GoodConfig_NoRevocationFinding()
    {
        var findings = new RevocationEndpointRule().Evaluate(Load("good-discovery.json")).ToList();
        findings.Should().BeEmpty();
    }

    [Fact]
    public void BadConfig_FlagsMissingRevocation()
    {
        var findings = new RevocationEndpointRule().Evaluate(Load("bad-discovery.json")).ToList();
        findings.Should().Contain(f => f.Id == "AG-REV-001");
    }

    [Fact]
    public void IssuerIdentification_FlagsMissingIssParameter()
    {
        var findings = new IssuerIdentificationRule().Evaluate(Load("bad-discovery.json")).ToList();
        findings.Should().Contain(f => f.Id == "AG-ISS-003");
    }

    [Fact]
    public void ClaimsScopes_FlagsMissingOpenIdScope()
    {
        var findings = new ClaimsScopesHygieneRule().Evaluate(Load("bad-discovery.json")).ToList();
        findings.Should().Contain(f => f.Id == "AG-SCOPE-002");
    }

    [Fact]
    public void EndSession_FlagsMissingLogout()
    {
        var findings = new EndSessionEndpointRule().Evaluate(Load("bad-discovery.json")).ToList();
        findings.Should().Contain(f => f.Id == "AG-LOGOUT-001");
    }

    [Fact]
    public void StrictProfile_NotesMissingPar()
    {
        var findings = new PushedAuthorizationRule()
            .Evaluate(Load("bad-discovery.json", profile: PolicyProfile.Strict))
            .ToList();
        findings.Should().Contain(f => f.Id == "AG-PAR-001");
    }
}
