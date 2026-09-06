namespace AuthGuard.Tests;

internal static class FixtureLoader
{
    public static string PathTo(string fileName) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", fileName);

    public static string Read(string fileName) =>
        File.ReadAllText(PathTo(fileName));
}
