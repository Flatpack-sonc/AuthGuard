using System.Text.Json;
using System.Text.Json.Serialization;
using AuthGuard.Core.Models;

namespace AuthGuard.Core.Baseline;

/// <summary>Read/write .authguard-baseline.json snapshots.</summary>
public static class BaselineStore
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static BaselineDocument FromAuditResult(AuditResult result, string? note = null)
    {
        ArgumentNullException.ThrowIfNull(result);
        // Baseline captures *active* findings (what you accept going forward).
        // If you want to baseline raw noise before suppressions, pass pre-suppression result.
        return new BaselineDocument
        {
            SchemaVersion = "1.0.0",
            Tool = "AuthGuard",
            Issuer = result.Issuer,
            CreatedAt = DateTimeOffset.UtcNow,
            Profile = result.Profile,
            Idp = result.Idp,
            Note = note,
            Findings = result.Findings.Select(f => new BaselineEntry
            {
                Id = f.Id,
                Severity = f.Severity,
                Title = f.Title,
                Reason = "Captured via authguard baseline / --write-baseline"
            }).ToList()
        };
    }

    /// <summary>
    /// Capture baseline from the union of active + currently suppressed-by-policy findings
    /// so a baseline freeze includes everything you currently live with.
    /// </summary>
    public static BaselineDocument FromAuditIncludingSuppressed(AuditResult result, string? note = null)
    {
        ArgumentNullException.ThrowIfNull(result);
        var all = result.Findings
            .Concat(result.SuppressedFindings.Select(s => s.Finding))
            .GroupBy(f => f.Id + "|" + f.Severity, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

        return new BaselineDocument
        {
            SchemaVersion = "1.0.0",
            Tool = "AuthGuard",
            Issuer = result.Issuer,
            CreatedAt = DateTimeOffset.UtcNow,
            Profile = result.Profile,
            Idp = result.Idp,
            Note = note ?? "Includes active + policy-suppressed findings at capture time.",
            Findings = all.Select(f => new BaselineEntry
            {
                Id = f.Id,
                Severity = f.Severity,
                Title = f.Title,
                Reason = "Captured via authguard baseline (include-suppressed)"
            }).ToList()
        };
    }

    public static BaselineDocument Load(string path)
    {
        var json = File.ReadAllText(path);
        var doc = JsonSerializer.Deserialize<BaselineDocument>(json, Options)
                  ?? throw new InvalidDataException($"Could not parse baseline: {path}");
        return doc;
    }

    public static void Save(BaselineDocument document, string path)
    {
        ArgumentNullException.ThrowIfNull(document);
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        File.WriteAllText(path, JsonSerializer.Serialize(document, Options));
    }
}
