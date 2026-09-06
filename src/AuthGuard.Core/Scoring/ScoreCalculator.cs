using AuthGuard.Core.Models;

namespace AuthGuard.Core.Scoring;

/// <summary>Weighted 0–100 score and A–F grade from findings.</summary>
public static class ScoreCalculator
{
    private static readonly Dictionary<Severity, int> Weights = new()
    {
        [Severity.Critical] = 25,
        [Severity.High] = 15,
        [Severity.Medium] = 8,
        [Severity.Low] = 3,
        [Severity.Info] = 1
    };

    public static int Calculate(IEnumerable<Finding> findings)
    {
        var penalty = findings.Sum(f => Weights.GetValueOrDefault(f.Severity, 0));
        // Cap so a flood of info findings cannot alone zero the score unrealistically,
        // but critical/high stacks still reach 0.
        var score = 100 - Math.Min(penalty, 100);
        return Math.Clamp(score, 0, 100);
    }

    public static Grade ToGrade(int score) => score switch
    {
        >= 90 => Grade.A,
        >= 80 => Grade.B,
        >= 70 => Grade.C,
        >= 60 => Grade.D,
        _ => Grade.F
    };

    public static (int Score, Grade Grade, SeverityCounts Counts) Evaluate(IEnumerable<Finding> findings)
    {
        var list = findings.ToList();
        var score = Calculate(list);
        return (score, ToGrade(score), SeverityCounts.FromFindings(list));
    }
}
