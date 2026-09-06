namespace AuthGuard.Core.Models;

/// <summary>
/// Items that cannot be verified from discovery metadata alone and require manual review.
/// </summary>
public sealed class ManualChecklistItem
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required string Guidance { get; init; }
    public IReadOnlyList<string> References { get; init; } = Array.Empty<string>();
}
