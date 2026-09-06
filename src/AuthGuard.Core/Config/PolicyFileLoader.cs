using System.Globalization;
using AuthGuard.Core.Models;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace AuthGuard.Core.Config;

/// <summary>Load and resolve .authguard.yml policy files.</summary>
public static class PolicyFileLoader
{
    public const string DefaultFileName = ".authguard.yml";
    public const string AlternateFileName = ".authguard.yaml";

    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    public static string? FindDefault(string? startDirectory = null)
    {
        var dir = new DirectoryInfo(string.IsNullOrWhiteSpace(startDirectory)
            ? Directory.GetCurrentDirectory()
            : startDirectory);

        while (dir is not null)
        {
            var yml = Path.Combine(dir.FullName, DefaultFileName);
            if (File.Exists(yml))
            {
                return yml;
            }

            var yaml = Path.Combine(dir.FullName, AlternateFileName);
            if (File.Exists(yaml))
            {
                return yaml;
            }

            dir = dir.Parent;
        }

        return null;
    }

    public static AuthGuardPolicyFile Parse(string yamlText)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(yamlText);
        return Deserializer.Deserialize<AuthGuardPolicyFile>(yamlText) ?? new AuthGuardPolicyFile();
    }

    public static AuthGuardPolicyFile Load(string path)
    {
        var text = File.ReadAllText(path);
        return Parse(text);
    }

    /// <summary>
    /// Resolve defaults + issuer-specific overrides into a flat policy.
    /// Issuer match is case-insensitive prefix/equals on normalized URLs.
    /// </summary>
    public static ResolvedPolicy Resolve(
        AuthGuardPolicyFile file,
        string? issuerUrl,
        string? sourcePath = null)
    {
        ArgumentNullException.ThrowIfNull(file);

        var suppressions = new List<SuppressionRule>();
        suppressions.AddRange(ParseSuppressions(file.Suppressions ?? []));

        PolicyProfile? profile = ParseProfile(file.Profile);
        IdpPreset? idp = ParseIdp(file.Idp);
        Severity? failOn = ParseSeverity(file.FailOn);
        var baseline = string.IsNullOrWhiteSpace(file.Baseline) ? null : file.Baseline.Trim();

        if (!string.IsNullOrWhiteSpace(issuerUrl) && (file.Issuers?.Count ?? 0) > 0)
        {
            var normalized = NormalizeUrl(issuerUrl);
            foreach (var ov in file.Issuers!)
            {
                if (ov is null || string.IsNullOrWhiteSpace(ov.Url))
                {
                    continue;
                }

                var ovNorm = NormalizeUrl(ov.Url);
                if (!normalized.StartsWith(ovNorm, StringComparison.OrdinalIgnoreCase)
                    && !ovNorm.StartsWith(normalized, StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(normalized, ovNorm, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (ParseProfile(ov.Profile) is { } p)
                {
                    profile = p;
                }

                if (ParseIdp(ov.Idp) is { } i)
                {
                    idp = i;
                }

                suppressions.AddRange(ParseSuppressions(ov.Suppressions ?? []));
            }
        }

        if (!string.IsNullOrWhiteSpace(baseline) && sourcePath is not null && !Path.IsPathRooted(baseline))
        {
            baseline = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(Path.GetFullPath(sourcePath))!, baseline));
        }

        return new ResolvedPolicy
        {
            SourcePath = sourcePath,
            Profile = profile,
            Idp = idp,
            FailOn = failOn,
            BaselinePath = baseline,
            Suppressions = Deduplicate(suppressions)
        };
    }

    public static string CreateSampleYaml() =>
        """
        # AuthGuard policy file — defensive configuration audit only
        # Docs: see README (Suppressions, Baseline, Drift)

        profile: standard          # relaxed | standard | strict
        idp: enterprise            # generic | spa | mobile | enterprise
        fail_on: high              # critical | high | medium | low | info
        baseline: .authguard-baseline.json

        # Global suppressions (require reason; optional until / ticket)
        suppressions:
          # - id: AG-FLOW-001
          #   reason: "Legacy hybrid kept for Outlook desktop until Q3 migration"
          #   until: 2027-01-01
          #   ticket: SEC-123

        # Per-issuer overrides (matched by URL prefix)
        issuers:
          # - url: https://login.microsoftonline.com/
          #   idp: enterprise
          #   suppressions:
          #     - id: AG-FLOW-001
          #       reason: "Entra advertises hybrid for legacy clients; accepted"
          #       until: 2027-06-01
        """;

    private static IEnumerable<SuppressionRule> ParseSuppressions(IEnumerable<SuppressionYaml?> items)
    {
        foreach (var item in items)
        {
            if (item is null)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(item.Id))
            {
                // Allow empty placeholder nodes from commented YAML samples
                if (string.IsNullOrWhiteSpace(item.Reason)
                    && string.IsNullOrWhiteSpace(item.Until)
                    && string.IsNullOrWhiteSpace(item.Ticket))
                {
                    continue;
                }

                throw new InvalidDataException("Each suppression requires an 'id' (e.g. AG-PKCE-001).");
            }

            if (string.IsNullOrWhiteSpace(item.Reason))
            {
                throw new InvalidDataException($"Suppression '{item.Id}' requires a non-empty 'reason'.");
            }

            DateOnly? until = null;
            if (!string.IsNullOrWhiteSpace(item.Until))
            {
                if (!DateOnly.TryParse(item.Until, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d))
                {
                    throw new InvalidDataException(
                        $"Suppression '{item.Id}' has invalid until date '{item.Until}'. Use YYYY-MM-DD.");
                }

                until = d;
            }

            Severity? onlySev = null;
            if (!string.IsNullOrWhiteSpace(item.OnlySeverity))
            {
                if (!Enum.TryParse(item.OnlySeverity, ignoreCase: true, out Severity sev))
                {
                    throw new InvalidDataException(
                        $"Suppression '{item.Id}' has invalid only_severity '{item.OnlySeverity}'.");
                }

                onlySev = sev;
            }

            yield return new SuppressionRule
            {
                Id = item.Id.Trim(),
                Reason = item.Reason.Trim(),
                Until = until,
                Ticket = string.IsNullOrWhiteSpace(item.Ticket) ? null : item.Ticket.Trim(),
                OnlySeverity = onlySev
            };
        }
    }

    private static IReadOnlyList<SuppressionRule> Deduplicate(List<SuppressionRule> rules)
    {
        // Last wins for same id+severity filter
        var map = new Dictionary<string, SuppressionRule>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in rules)
        {
            var key = $"{r.Id}|{r.OnlySeverity?.ToString() ?? "*"}";
            map[key] = r;
        }

        return map.Values.ToList();
    }

    private static PolicyProfile? ParseProfile(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? null
            : Enum.TryParse<PolicyProfile>(value.Trim(), ignoreCase: true, out var p)
                ? p
                : throw new InvalidDataException($"Invalid profile '{value}'. Use relaxed, standard, or strict.");

    private static IdpPreset? ParseIdp(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? null
            : Enum.TryParse<IdpPreset>(value.Trim(), ignoreCase: true, out var p)
                ? p
                : throw new InvalidDataException($"Invalid idp '{value}'. Use generic, spa, mobile, or enterprise.");

    private static Severity? ParseSeverity(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? null
            : Enum.TryParse<Severity>(value.Trim(), ignoreCase: true, out var s)
                ? s
                : throw new InvalidDataException($"Invalid fail_on '{value}'.");

    private static string NormalizeUrl(string url)
    {
        url = url.Trim().TrimEnd('/');
        if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            url = "https://" + url;
        }

        return url.ToLowerInvariant();
    }
}
