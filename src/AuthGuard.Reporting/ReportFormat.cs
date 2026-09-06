namespace AuthGuard.Reporting;

public enum ReportFormat
{
    Console,
    Json,
    Sarif,
    Html
}

public static class ReportFormatParser
{
    public static bool TryParse(string? value, out ReportFormat format)
    {
        format = ReportFormat.Console;
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        return Enum.TryParse(value.Trim(), ignoreCase: true, out format);
    }
}
