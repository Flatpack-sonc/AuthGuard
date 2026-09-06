using AuthGuard.Core;
using AuthGuard.Core.Models;
using FluentAssertions;

namespace AuthGuard.Tests;

public class AuditServiceTests
{
    [Fact]
    public async Task OfflineGoodConfig_ScoresWell()
    {
        var service = new AuditService();
        var result = await service.AuditAsync(new AuditOptions
        {
            OfflineConfigPath = FixtureLoader.PathTo("good-discovery.json"),
            OfflineJwksPath = FixtureLoader.PathTo("good-jwks.json"),
            Profile = PolicyProfile.Standard
        });

        result.Issuer.Should().Be("https://good.example.com");
        result.Score.Should().BeGreaterThanOrEqualTo(90);
        result.Grade.Should().Be(Grade.A);
        result.Findings.Should().OnlyContain(f => f.Severity <= Severity.Low);
        result.ManualChecklist.Should().NotBeEmpty();
        result.DiscoverySource.Should().StartWith("offline:");
    }

    [Fact]
    public async Task OfflineBadConfig_FailsHard()
    {
        var service = new AuditService();
        var result = await service.AuditAsync(new AuditOptions
        {
            OfflineConfigPath = FixtureLoader.PathTo("bad-discovery.json"),
            OfflineJwksPath = FixtureLoader.PathTo("bad-jwks.json"),
            Profile = PolicyProfile.Standard
        });

        result.Score.Should().BeLessThan(60);
        result.Grade.Should().Be(Grade.F);
        result.Counts.Critical.Should().BeGreaterThan(0);
        result.Findings.Select(f => f.Id).Should().Contain(new[]
        {
            "AG-PKCE-001",
            "AG-FLOW-001",
            "AG-GRANT-001",
            "AG-ALG-002",
            "AG-TLS-002"
        });
    }

    [Fact]
    public async Task StrictProfile_ProducesMoreOrEqualFindings()
    {
        var service = new AuditService();
        var standard = await service.AuditAsync(new AuditOptions
        {
            OfflineConfigPath = FixtureLoader.PathTo("pkce-plain-only.json"),
            OfflineJwksPath = FixtureLoader.PathTo("empty-ish-jwks.json"),
            Profile = PolicyProfile.Standard
        });
        var strict = await service.AuditAsync(new AuditOptions
        {
            OfflineConfigPath = FixtureLoader.PathTo("pkce-plain-only.json"),
            OfflineJwksPath = FixtureLoader.PathTo("empty-ish-jwks.json"),
            Profile = PolicyProfile.Strict
        });

        strict.Findings.Count.Should().BeGreaterThanOrEqualTo(standard.Findings.Count);
        strict.Findings.Should().Contain(f => f.Id == "AG-PKCE-003");
    }
}
