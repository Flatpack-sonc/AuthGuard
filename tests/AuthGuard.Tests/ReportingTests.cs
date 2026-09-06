using System.Text.Json;
using AuthGuard.Core;
using AuthGuard.Core.Models;
using AuthGuard.Reporting;
using FluentAssertions;

namespace AuthGuard.Tests;

public class ReportingTests
{
    [Fact]
    public async Task JsonReport_HasStableSchema()
    {
        var result = await RunOfflineAsync("good-discovery.json", "good-jwks.json");
        var json = JsonReportWriter.Write(result);
        using var doc = JsonDocument.Parse(json);
        doc.RootElement.GetProperty("schemaVersion").GetString().Should().Be("1.1.0");
        doc.RootElement.GetProperty("issuer").GetString().Should().Be("https://good.example.com");
        doc.RootElement.GetProperty("score").GetInt32().Should().BeInRange(0, 100);
        doc.RootElement.GetProperty("findings").ValueKind.Should().Be(JsonValueKind.Array);
        doc.RootElement.GetProperty("manualChecklist").GetArrayLength().Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task SarifReport_IsValidShape()
    {
        var result = await RunOfflineAsync("bad-discovery.json", "bad-jwks.json");
        var sarif = SarifReportWriter.Write(result);
        using var doc = JsonDocument.Parse(sarif);
        doc.RootElement.GetProperty("version").GetString().Should().Be("2.1.0");
        var runs = doc.RootElement.GetProperty("runs");
        runs.GetArrayLength().Should().Be(1);
        var run = runs[0];
        run.GetProperty("tool").GetProperty("driver").GetProperty("name").GetString().Should().Be("AuthGuard");
        run.GetProperty("results").GetArrayLength().Should().Be(result.Findings.Count);
        run.GetProperty("tool").GetProperty("driver").GetProperty("rules").GetArrayLength()
            .Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task HtmlReport_ContainsIssuerAndScore()
    {
        var result = await RunOfflineAsync("good-discovery.json", "good-jwks.json");
        var html = HtmlReportWriter.Write(result);
        html.Should().Contain("AuthGuard");
        html.Should().Contain("https://good.example.com");
        html.Should().Contain($"{result.Score}/100");
        html.Should().Contain("Manual verification checklist");
    }

    [Fact]
    public void ExitCode_FailsOnHigh()
    {
        var findings = new[]
        {
            new Finding
            {
                Id = "AG-X",
                Title = "t",
                Severity = Severity.High,
                Description = "d",
                Evidence = "e",
                Remediation = "r"
            }
        };
        ExitCodeEvaluator.FromFindings(findings, Severity.High).Should().Be(1);
        ExitCodeEvaluator.FromFindings(findings, Severity.Critical).Should().Be(0);
    }

    private static async Task<AuditResult> RunOfflineAsync(string discovery, string jwks)
    {
        var service = new AuditService();
        return await service.AuditAsync(new AuditOptions
        {
            OfflineConfigPath = FixtureLoader.PathTo(discovery),
            OfflineJwksPath = FixtureLoader.PathTo(jwks),
            Profile = PolicyProfile.Standard
        });
    }
}
