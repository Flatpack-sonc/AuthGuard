using System.Text.Json;
using System.Text.Json.Serialization;
using AuthGuard.Core.Models;

namespace AuthGuard.Reporting;

/// <summary>SARIF 2.1.0 writer for GitHub Code Scanning-style CI.</summary>
public static class SarifReportWriter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string Write(AuditResult result)
    {
        var rules = result.Findings
            .GroupBy(f => f.Id)
            .Select(g => g.First())
            .Select(f => new SarifReportingDescriptor
            {
                Id = f.Id,
                Name = SanitizeName(f.Id),
                ShortDescription = new SarifMessage { Text = f.Title },
                FullDescription = new SarifMessage { Text = f.Description },
                HelpUri = f.References.FirstOrDefault(),
                Help = new SarifMessage { Text = f.Remediation },
                DefaultConfiguration = new SarifReportingConfiguration
                {
                    Level = ToLevel(f.Severity)
                },
                Properties = new Dictionary<string, object?>
                {
                    ["category"] = f.RuleCategory,
                    ["severity"] = f.Severity.ToString()
                }
            })
            .ToList();

        var results = result.Findings.Select(f => new SarifResult
        {
            RuleId = f.Id,
            Level = ToLevel(f.Severity),
            Message = new SarifMessage
            {
                Text = $"{f.Title}. {f.Description} Evidence: {f.Evidence}. Remediation: {f.Remediation}"
            },
            Locations =
            [
                new SarifLocation
                {
                    PhysicalLocation = new SarifPhysicalLocation
                    {
                        ArtifactLocation = new SarifArtifactLocation
                        {
                            Uri = result.DiscoverySource ?? result.Issuer,
                            UriBaseId = "%OIDC_ISSUER%"
                        }
                    }
                }
            ],
            Properties = new Dictionary<string, object?>
            {
                ["evidence"] = f.Evidence,
                ["remediation"] = f.Remediation,
                ["references"] = f.References.ToList()
            }
        }).ToList();

        var sarif = new SarifLog
        {
            Schema = "https://json.schemastore.org/sarif-2.1.0.json",
            Version = "2.1.0",
            Runs =
            [
                new SarifRun
                {
                    Tool = new SarifTool
                    {
                        Driver = new SarifToolComponent
                        {
                            Name = "AuthGuard",
                            InformationUri = "https://github.com/authguard/authguard",
                            Version = result.ToolVersion,
                            SemanticVersion = result.ToolVersion,
                            Rules = rules
                        }
                    },
                    Results = results,
                    Properties = new Dictionary<string, object?>
                    {
                        ["issuer"] = result.Issuer,
                        ["profile"] = result.Profile.ToString(),
                        ["score"] = result.Score,
                        ["grade"] = result.Grade.ToString(),
                        ["auditedAt"] = result.AuditedAt.ToString("O")
                    }
                }
            ]
        };

        return JsonSerializer.Serialize(sarif, Options);
    }

    public static void WriteToFile(AuditResult result, string path) =>
        File.WriteAllText(path, Write(result));

    private static string ToLevel(Severity severity) => severity switch
    {
        Severity.Critical => "error",
        Severity.High => "error",
        Severity.Medium => "warning",
        Severity.Low => "note",
        _ => "none"
    };

    private static string SanitizeName(string id) =>
        id.Replace('-', '_');
}

internal sealed class SarifLog
{
    [JsonPropertyName("$schema")]
    public string Schema { get; set; } = "";

    public string Version { get; set; } = "2.1.0";
    public List<SarifRun> Runs { get; set; } = [];
}

internal sealed class SarifRun
{
    public SarifTool Tool { get; set; } = new();
    public List<SarifResult> Results { get; set; } = [];
    public Dictionary<string, object?>? Properties { get; set; }
}

internal sealed class SarifTool
{
    public SarifToolComponent Driver { get; set; } = new();
}

internal sealed class SarifToolComponent
{
    public string Name { get; set; } = "";
    public string? InformationUri { get; set; }
    public string? Version { get; set; }
    public string? SemanticVersion { get; set; }
    public List<SarifReportingDescriptor> Rules { get; set; } = [];
}

internal sealed class SarifReportingDescriptor
{
    public string Id { get; set; } = "";
    public string? Name { get; set; }
    public SarifMessage? ShortDescription { get; set; }
    public SarifMessage? FullDescription { get; set; }
    public string? HelpUri { get; set; }
    public SarifMessage? Help { get; set; }
    public SarifReportingConfiguration? DefaultConfiguration { get; set; }
    public Dictionary<string, object?>? Properties { get; set; }
}

internal sealed class SarifReportingConfiguration
{
    public string Level { get; set; } = "warning";
}

internal sealed class SarifResult
{
    public string RuleId { get; set; } = "";
    public string Level { get; set; } = "warning";
    public SarifMessage Message { get; set; } = new();
    public List<SarifLocation>? Locations { get; set; }
    public Dictionary<string, object?>? Properties { get; set; }
}

internal sealed class SarifMessage
{
    public string Text { get; set; } = "";
}

internal sealed class SarifLocation
{
    public SarifPhysicalLocation? PhysicalLocation { get; set; }
}

internal sealed class SarifPhysicalLocation
{
    public SarifArtifactLocation? ArtifactLocation { get; set; }
}

internal sealed class SarifArtifactLocation
{
    public string Uri { get; set; } = "";
    public string? UriBaseId { get; set; }
}
