using AuthGuard.Core.Models;
using AuthGuard.Core.Scoring;
using FluentAssertions;

namespace AuthGuard.Tests;

public class ScoreCalculatorTests
{
    [Fact]
    public void PerfectScore_WhenNoFindings()
    {
        var (score, grade, counts) = ScoreCalculator.Evaluate(Array.Empty<Finding>());
        score.Should().Be(100);
        grade.Should().Be(Grade.A);
        counts.Total.Should().Be(0);
    }

    [Fact]
    public void CriticalFinding_DropsScoreSignificantly()
    {
        var findings = new[]
        {
            Make("AG-X", Severity.Critical)
        };
        var score = ScoreCalculator.Calculate(findings);
        score.Should().Be(75);
        ScoreCalculator.ToGrade(score).Should().Be(Grade.C);
    }

    [Fact]
    public void ManyFindings_FloorAtZero()
    {
        var findings = Enumerable.Range(0, 10)
            .Select(i => Make($"AG-{i}", Severity.Critical));
        ScoreCalculator.Calculate(findings).Should().Be(0);
        ScoreCalculator.ToGrade(0).Should().Be(Grade.F);
    }

    [Theory]
    [InlineData(95, Grade.A)]
    [InlineData(85, Grade.B)]
    [InlineData(75, Grade.C)]
    [InlineData(65, Grade.D)]
    [InlineData(50, Grade.F)]
    public void GradeBoundaries(int score, Grade expected)
    {
        ScoreCalculator.ToGrade(score).Should().Be(expected);
    }

    private static Finding Make(string id, Severity severity) => new()
    {
        Id = id,
        Title = "t",
        Severity = severity,
        Description = "d",
        Evidence = "e",
        Remediation = "r"
    };
}
