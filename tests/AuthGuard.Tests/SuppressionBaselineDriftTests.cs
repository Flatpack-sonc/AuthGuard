using AuthGuard.Core;
using AuthGuard.Core.Baseline;
using AuthGuard.Core.Config;
using AuthGuard.Core.Drift;
using AuthGuard.Core.Models;
using AuthGuard.Core.Policy;
using AuthGuard.Core.Suppressions;
using AuthGuard.Reporting;
using FluentAssertions;

namespace AuthGuard.Tests;

public class SuppressionBaselineDriftTests
{
    [Fact]
    public void PolicyFile_ParsesSuppressionsWithExpiry()
    {
        var yaml = """
            profile: strict
            idp: spa
            fail_on: medium
            suppressions:
              - id: AG-PKCE-001
                reason: Accepted until migration
                until: 2099-01-01
                ticket: SEC-1
            """;
        var file = PolicyFileLoader.Parse(yaml);
        var resolved = PolicyFileLoader.Resolve(file, "https://example.com");
        resolved.Profile.Should().Be(PolicyProfile.Strict);
        resolved.Idp.Should().Be(IdpPreset.Spa);
        resolved.FailOn.Should().Be(Severity.Medium);
        resolved.Suppressions.Should().ContainSingle(s => s.Id == "AG-PKCE-001" && s.Ticket == "SEC-1");
    }

    [Fact]
    public void SuppressionEngine_MutesMatchingFinding()
    {
        var findings = new[]
        {
            new Finding
            {
                Id = "AG-PKCE-001",
                Title = "PKCE",
                Severity = Severity.High,
                Description = "d",
                Evidence = "e",
                Remediation = "r"
            },
            new Finding
            {
                Id = "AG-ALG-001",
                Title = "Alg",
                Severity = Severity.Medium,
                Description = "d",
                Evidence = "e",
                Remediation = "r"
            }
        };

        var result = SuppressionEngine.Apply(findings,
        [
            new SuppressionRule { Id = "AG-PKCE-001", Reason = "tracked" }
        ]);

        result.Active.Should().ContainSingle(f => f.Id == "AG-ALG-001");
        result.Suppressed.Should().ContainSingle(s => s.Finding.Id == "AG-PKCE-001");
    }

    [Fact]
    public void SuppressionEngine_ExpiredDoesNotMute()
    {
        var findings = new[]
        {
            new Finding
            {
                Id = "AG-PKCE-001",
                Title = "PKCE",
                Severity = Severity.High,
                Description = "d",
                Evidence = "e",
                Remediation = "r"
            }
        };

        var result = SuppressionEngine.Apply(
            findings,
            [new SuppressionRule { Id = "AG-PKCE-001", Reason = "old", Until = new DateOnly(2020, 1, 1) }],
            todayUtc: new DateOnly(2026, 9, 6));

        result.Active.Should().ContainSingle();
        result.ExpiredRules.Should().ContainSingle();
    }

    [Fact]
    public void Baseline_MutesKnownIds()
    {
        var findings = new[]
        {
            new Finding
            {
                Id = "AG-FLOW-001",
                Title = "Hybrid",
                Severity = Severity.Medium,
                Description = "d",
                Evidence = "e",
                Remediation = "r"
            }
        };

        var baseline = new BaselineDocument
        {
            Findings =
            [
                new BaselineEntry { Id = "AG-FLOW-001", Severity = Severity.Medium, Reason = "accepted" }
            ]
        };

        var result = SuppressionEngine.Apply(findings, baseline: baseline);
        result.Active.Should().BeEmpty();
        result.Suppressed.Should().ContainSingle(s => s.Source == SuppressionSource.Baseline);
    }

    [Fact]
    public void Drift_DetectsAddedAndResolved()
    {
        var prev = new[]
        {
            new Finding
            {
                Id = "AG-A",
                Title = "a",
                Severity = Severity.High,
                Description = "d",
                Evidence = "e",
                Remediation = "r"
            }
        };
        var curr = new[]
        {
            new Finding
            {
                Id = "AG-B",
                Title = "b",
                Severity = Severity.Critical,
                Description = "d",
                Evidence = "e",
                Remediation = "r"
            }
        };

        var report = DriftComparer.CompareFindings(prev, curr, "p", "c");
        report.Resolved.Should().ContainSingle(i => i.Id == "AG-A");
        report.Added.Should().ContainSingle(i => i.Id == "AG-B");
        report.HasRegressions.Should().BeTrue();
        DriftReportWriter.ExitCode(report, Severity.High).Should().Be(1);
    }

    [Fact]
    public void IdpPreset_EnterpriseDowngradesFlowNoise()
    {
        var findings = new[]
        {
            new Finding
            {
                Id = "AG-FLOW-001",
                Title = "Hybrid",
                Severity = Severity.High,
                Description = "d",
                Evidence = "e",
                Remediation = "r"
            }
        };

        var adjusted = IdpPresetAdjuster.Apply(findings, IdpPreset.Enterprise);
        adjusted.Single().Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public async Task AuditService_AppliesSuppressionsAndRescores()
    {
        var without = await new AuditService().AuditAsync(new AuditOptions
        {
            OfflineConfigPath = FixtureLoader.PathTo("bad-discovery.json"),
            OfflineJwksPath = FixtureLoader.PathTo("bad-jwks.json"),
            Profile = PolicyProfile.Standard,
            Idp = IdpPreset.Generic
        });

        without.Findings.Should().NotBeEmpty();
        var ids = without.Findings.Select(f => f.Id).Distinct().Take(3).ToList();
        ids.Should().NotBeEmpty();

        var with = await new AuditService().AuditAsync(new AuditOptions
        {
            OfflineConfigPath = FixtureLoader.PathTo("bad-discovery.json"),
            OfflineJwksPath = FixtureLoader.PathTo("bad-jwks.json"),
            Profile = PolicyProfile.Standard,
            Suppressions = ids.Select(id => new SuppressionRule { Id = id, Reason = "test" }).ToList()
        });

        with.SuppressedFindings.Count.Should().BeGreaterThanOrEqualTo(ids.Count);
        with.Score.Should().BeGreaterThanOrEqualTo(without.Score);
    }

    [Fact]
    public async Task JsonReport_IncludesSuppressedSection()
    {
        var result = await new AuditService().AuditAsync(new AuditOptions
        {
            OfflineConfigPath = FixtureLoader.PathTo("bad-discovery.json"),
            OfflineJwksPath = FixtureLoader.PathTo("bad-jwks.json"),
            Suppressions = [new SuppressionRule { Id = "AG-PKCE-001", Reason = "ci" }]
        });

        var json = JsonReportWriter.Write(result);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        doc.RootElement.GetProperty("schemaVersion").GetString().Should().Be("1.1.0");
        doc.RootElement.GetProperty("suppressedFindings").ValueKind.Should().Be(System.Text.Json.JsonValueKind.Array);
        doc.RootElement.GetProperty("idp").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void BaselineStore_RoundTrip()
    {
        var path = Path.Combine(Path.GetTempPath(), "ag-baseline-" + Guid.NewGuid().ToString("n") + ".json");
        try
        {
            var doc = new BaselineDocument
            {
                Issuer = "https://example.com",
                Findings = [new BaselineEntry { Id = "AG-X", Severity = Severity.High, Title = "t" }]
            };
            BaselineStore.Save(doc, path);
            var loaded = BaselineStore.Load(path);
            loaded.Findings.Should().ContainSingle(f => f.Id == "AG-X");
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void SamplePolicyYaml_IsValid()
    {
        var parsed = PolicyFileLoader.Parse(PolicyFileLoader.CreateSampleYaml());
        parsed.Should().NotBeNull();
        var resolved = PolicyFileLoader.Resolve(parsed, null);
        resolved.Profile.Should().Be(PolicyProfile.Standard);
        resolved.Idp.Should().Be(IdpPreset.Enterprise);
    }
}
