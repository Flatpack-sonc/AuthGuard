using AuthGuard.Core.Models;

namespace AuthGuard.Core.Drift;

public enum DriftChangeKind
{
    Added,
    Resolved,
    SeverityIncreased,
    SeverityDecreased,
    Unchanged
}

public sealed class DriftItem
{
    public required string Id { get; init; }
    public required DriftChangeKind Kind { get; init; }
    public string? Title { get; init; }
    public Severity? PreviousSeverity { get; init; }
    public Severity? CurrentSeverity { get; init; }
}

public sealed class DriftReport
{
    public required string PreviousLabel { get; init; }
    public required string CurrentLabel { get; init; }
    public DateTimeOffset ComparedAt { get; init; } = DateTimeOffset.UtcNow;
    public required IReadOnlyList<DriftItem> Items { get; init; }

    public IReadOnlyList<DriftItem> Added => Items.Where(i => i.Kind == DriftChangeKind.Added).ToList();
    public IReadOnlyList<DriftItem> Resolved => Items.Where(i => i.Kind == DriftChangeKind.Resolved).ToList();
    public IReadOnlyList<DriftItem> SeverityIncreased =>
        Items.Where(i => i.Kind == DriftChangeKind.SeverityIncreased).ToList();
    public IReadOnlyList<DriftItem> SeverityDecreased =>
        Items.Where(i => i.Kind == DriftChangeKind.SeverityDecreased).ToList();
    public IReadOnlyList<DriftItem> Unchanged => Items.Where(i => i.Kind == DriftChangeKind.Unchanged).ToList();

    public bool HasRegressions => Added.Count > 0 || SeverityIncreased.Count > 0;
}

/// <summary>Compare two sets of findings (JSON reports or live vs baseline).</summary>
public static class DriftComparer
{
    public static DriftReport Compare(
        IEnumerable<(string Id, Severity Severity, string? Title)> previous,
        IEnumerable<(string Id, Severity Severity, string? Title)> current,
        string previousLabel,
        string currentLabel)
    {
        var prevMap = previous
            .GroupBy(x => x.Id, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(x => x.Severity).First(), StringComparer.OrdinalIgnoreCase);

        var currMap = current
            .GroupBy(x => x.Id, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(x => x.Severity).First(), StringComparer.OrdinalIgnoreCase);

        var ids = prevMap.Keys.Union(currMap.Keys, StringComparer.OrdinalIgnoreCase)
            .OrderBy(id => id, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var items = new List<DriftItem>();
        foreach (var id in ids)
        {
            var hasPrev = prevMap.TryGetValue(id, out var p);
            var hasCurr = currMap.TryGetValue(id, out var c);

            if (hasPrev && !hasCurr)
            {
                items.Add(new DriftItem
                {
                    Id = id,
                    Kind = DriftChangeKind.Resolved,
                    Title = p.Title,
                    PreviousSeverity = p.Severity
                });
                continue;
            }

            if (!hasPrev && hasCurr)
            {
                items.Add(new DriftItem
                {
                    Id = id,
                    Kind = DriftChangeKind.Added,
                    Title = c.Title,
                    CurrentSeverity = c.Severity
                });
                continue;
            }

            if (hasPrev && hasCurr)
            {
                if (p.Severity == c.Severity)
                {
                    items.Add(new DriftItem
                    {
                        Id = id,
                        Kind = DriftChangeKind.Unchanged,
                        Title = c.Title ?? p.Title,
                        PreviousSeverity = p.Severity,
                        CurrentSeverity = c.Severity
                    });
                }
                else if (c.Severity > p.Severity)
                {
                    items.Add(new DriftItem
                    {
                        Id = id,
                        Kind = DriftChangeKind.SeverityIncreased,
                        Title = c.Title ?? p.Title,
                        PreviousSeverity = p.Severity,
                        CurrentSeverity = c.Severity
                    });
                }
                else
                {
                    items.Add(new DriftItem
                    {
                        Id = id,
                        Kind = DriftChangeKind.SeverityDecreased,
                        Title = c.Title ?? p.Title,
                        PreviousSeverity = p.Severity,
                        CurrentSeverity = c.Severity
                    });
                }
            }
        }

        return new DriftReport
        {
            PreviousLabel = previousLabel,
            CurrentLabel = currentLabel,
            Items = items
        };
    }

    public static DriftReport CompareFindings(
        IEnumerable<Finding> previous,
        IEnumerable<Finding> current,
        string previousLabel,
        string currentLabel) =>
        Compare(
            previous.Select(f => (f.Id, f.Severity, (string?)f.Title)),
            current.Select(f => (f.Id, f.Severity, (string?)f.Title)),
            previousLabel,
            currentLabel);

    public static DriftReport CompareToBaseline(
        BaselineDocument baseline,
        IEnumerable<Finding> current,
        string currentLabel = "current") =>
        Compare(
            baseline.Findings.Select(f => (f.Id, f.Severity ?? Severity.Info, f.Title)),
            current.Select(f => (f.Id, f.Severity, (string?)f.Title)),
            baseline.Issuer is null ? "baseline" : $"baseline:{baseline.Issuer}",
            currentLabel);
}
