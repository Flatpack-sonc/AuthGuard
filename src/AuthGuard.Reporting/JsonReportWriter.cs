using System.Text.Json;
using System.Text.Json.Serialization;
using AuthGuard.Core.Models;

namespace AuthGuard.Reporting;

/// <summary>Stable JSON audit report schema (v1.1 — suppressions / baseline / idp).</summary>
public static class JsonReportWriter
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static string Write(AuditResult result)
    {
        var dto = ToDto(result);
        return JsonSerializer.Serialize(dto, Options);
    }

    public static JsonAuditReport ToDto(AuditResult result)
    {
        return new JsonAuditReport
        {
            SchemaVersion = "1.1.0",
            Tool = new JsonToolInfo { Name = "AuthGuard", Version = result.ToolVersion },
            Issuer = result.Issuer,
            AuditedAt = result.AuditedAt,
            Profile = result.Profile,
            Idp = result.Idp,
            Score = result.Score,
            Grade = result.Grade,
            DiscoverySource = result.DiscoverySource,
            PolicyFile = result.PolicyFilePath,
            Baseline = result.BaselinePath,
            Assumptions = result.Assumptions.ToList(),
            Counts = new JsonSeverityCounts
            {
                Critical = result.Counts.Critical,
                High = result.Counts.High,
                Medium = result.Counts.Medium,
                Low = result.Counts.Low,
                Info = result.Counts.Info,
                Total = result.Counts.Total
            },
            Findings = result.Findings.Select(MapFinding).ToList(),
            SuppressedFindings = result.SuppressedFindings.Select(s => new JsonSuppressedFinding
            {
                Finding = MapFinding(s.Finding),
                Reason = s.Reason,
                Source = s.Source.ToString(),
                Until = s.Until?.ToString("yyyy-MM-dd"),
                Ticket = s.Ticket
            }).ToList(),
            ExpiredSuppressions = result.ExpiredSuppressions.Select(r => new JsonExpiredSuppression
            {
                Id = r.Id,
                Reason = r.Reason,
                Until = r.Until?.ToString("yyyy-MM-dd"),
                Ticket = r.Ticket
            }).ToList(),
            ManualChecklist = result.ManualChecklist.Select(m => new JsonManualItem
            {
                Id = m.Id,
                Title = m.Title,
                Guidance = m.Guidance,
                References = m.References.ToList()
            }).ToList()
        };
    }

    public static JsonAuditReport Read(string json)
    {
        return JsonSerializer.Deserialize<JsonAuditReport>(json, Options)
               ?? throw new InvalidDataException("Invalid AuthGuard JSON report.");
    }

    public static JsonAuditReport ReadFile(string path) => Read(File.ReadAllText(path));

    public static void WriteToFile(AuditResult result, string path) =>
        File.WriteAllText(path, Write(result));

    private static JsonFinding MapFinding(Finding f) => new()
    {
        Id = f.Id,
        Title = f.Title,
        Severity = f.Severity,
        Description = f.Description,
        Evidence = f.Evidence,
        Remediation = f.Remediation,
        References = f.References.ToList(),
        RuleCategory = f.RuleCategory
    };
}

public sealed class JsonAuditReport
{
    public string SchemaVersion { get; set; } = "1.1.0";
    public JsonToolInfo Tool { get; set; } = new();
    public string Issuer { get; set; } = "";
    public DateTimeOffset AuditedAt { get; set; }
    public PolicyProfile Profile { get; set; }
    public IdpPreset Idp { get; set; }
    public int Score { get; set; }
    public Grade Grade { get; set; }
    public string? DiscoverySource { get; set; }
    public string? PolicyFile { get; set; }
    public string? Baseline { get; set; }
    public List<string> Assumptions { get; set; } = [];
    public JsonSeverityCounts Counts { get; set; } = new();
    public List<JsonFinding> Findings { get; set; } = [];
    public List<JsonSuppressedFinding> SuppressedFindings { get; set; } = [];
    public List<JsonExpiredSuppression> ExpiredSuppressions { get; set; } = [];
    public List<JsonManualItem> ManualChecklist { get; set; } = [];
}

public sealed class JsonToolInfo
{
    public string Name { get; set; } = "AuthGuard";
    public string Version { get; set; } = "1.1.0";
}

public sealed class JsonSeverityCounts
{
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Info { get; set; }
    public int Total { get; set; }
}

public sealed class JsonFinding
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public Severity Severity { get; set; }
    public string Description { get; set; } = "";
    public string Evidence { get; set; } = "";
    public string Remediation { get; set; } = "";
    public List<string> References { get; set; } = [];
    public string? RuleCategory { get; set; }
}

public sealed class JsonSuppressedFinding
{
    public JsonFinding Finding { get; set; } = new();
    public string Reason { get; set; } = "";
    public string Source { get; set; } = "";
    public string? Until { get; set; }
    public string? Ticket { get; set; }
}

public sealed class JsonExpiredSuppression
{
    public string Id { get; set; } = "";
    public string Reason { get; set; } = "";
    public string? Until { get; set; }
    public string? Ticket { get; set; }
}

public sealed class JsonManualItem
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string Guidance { get; set; } = "";
    public List<string> References { get; set; } = [];
}
