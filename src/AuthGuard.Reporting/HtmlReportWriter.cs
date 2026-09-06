using System.Net;
using System.Text;
using AuthGuard.Core.Models;

namespace AuthGuard.Reporting;

/// <summary>Single-file HTML audit report (no external dependencies).</summary>
public static class HtmlReportWriter
{
    public static string Write(AuditResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset=\"utf-8\"/>");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>");
        sb.AppendLine("<title>AuthGuard Audit Report</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("""
            :root {
              --bg: #0b1220;
              --panel: #121c2e;
              --panel2: #18243a;
              --text: #e8eef7;
              --muted: #93a0b5;
              --accent: #5eb1ff;
              --critical: #ff5c5c;
              --high: #ff8a3d;
              --medium: #f0c14d;
              --low: #7eb6ff;
              --info: #8b9bb4;
              --ok: #3ecf8e;
              --line: #2a3a52;
            }
            * { box-sizing: border-box; }
            body {
              margin: 0;
              font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
              background:
                radial-gradient(1200px 600px at 10% -10%, #1a2b4a 0%, transparent 55%),
                radial-gradient(900px 500px at 100% 0%, #142033 0%, transparent 50%),
                var(--bg);
              color: var(--text);
              line-height: 1.55;
              min-height: 100vh;
            }
            .wrap { max-width: 980px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
            header h1 { margin: 0 0 .2rem; font-size: 1.85rem; letter-spacing: .01em; }
            header .tag {
              display: inline-block; font-size: .72rem; text-transform: uppercase; letter-spacing: .08em;
              color: var(--accent); border: 1px solid #2d4f73; background: #152338; padding: .15rem .5rem; border-radius: 999px;
            }
            header p { margin: .55rem 0 0; color: var(--muted); max-width: 46rem; }
            .score {
              display: flex; gap: 1.5rem; flex-wrap: wrap; align-items: center;
              background: linear-gradient(180deg, var(--panel2), var(--panel));
              border: 1px solid var(--line); border-radius: 14px;
              padding: 1.25rem 1.5rem; margin: 1.5rem 0; box-shadow: 0 10px 40px rgba(0,0,0,.25);
            }
            .grade {
              width: 78px; height: 78px; border-radius: 14px; display: grid; place-items: center;
              font-size: 2.1rem; font-weight: 700; background: #1c2c44; border: 1px solid var(--line);
            }
            .meta { color: var(--muted); font-size: .92rem; }
            .meta strong { color: var(--text); }
            .counts { display: flex; gap: .55rem; flex-wrap: wrap; margin-top: .75rem; }
            .chip {
              font-size: .78rem; padding: .22rem .65rem; border-radius: 999px;
              background: #1b2a40; border: 1px solid #314862;
            }
            h2 { margin-top: 2.1rem; font-size: 1.12rem; border-bottom: 1px solid var(--line); padding-bottom: .45rem; }
            .finding, .suppressed {
              background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
              padding: 1rem 1.1rem; margin: .85rem 0; border-left: 4px solid var(--info);
            }
            .finding.critical { border-left-color: var(--critical); }
            .finding.high { border-left-color: var(--high); }
            .finding.medium { border-left-color: var(--medium); }
            .finding.low { border-left-color: var(--low); }
            .finding.info { border-left-color: var(--info); }
            .suppressed { opacity: .88; border-left-color: #4a5d78; }
            .finding h3, .suppressed h3 { margin: 0 0 .35rem; font-size: 1rem; }
            .sev { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
            .finding p, .suppressed p { margin: .4rem 0; }
            .label { color: var(--muted); font-size: .85rem; }
            ul.refs { margin: .3rem 0 0; padding-left: 1.2rem; color: var(--muted); font-size: .85rem; }
            a { color: var(--accent); }
            .assumptions li, .manual li { margin: .4rem 0; color: var(--muted); }
            footer { margin-top: 2.5rem; color: var(--muted); font-size: .8rem; }
            .empty { color: var(--ok); }
            """);
        sb.AppendLine("</style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body><div class=\"wrap\">");

        sb.AppendLine("<header>");
        sb.AppendLine("<span class=\"tag\">Defensive configuration audit</span>");
        sb.AppendLine("<h1>AuthGuard</h1>");
        sb.AppendLine("<p>OAuth / OIDC / JWT metadata hardening report with suppressions, baseline, and IdP-aware scoring.</p>");
        sb.AppendLine("</header>");

        sb.AppendLine("<div class=\"score\">");
        sb.AppendLine($"<div class=\"grade\">{E(result.Grade.ToString())}</div>");
        sb.AppendLine("<div>");
        sb.AppendLine($"<div class=\"meta\"><strong>Issuer:</strong> {E(result.Issuer)}</div>");
        sb.AppendLine($"<div class=\"meta\"><strong>Score:</strong> {result.Score}/100 &nbsp;|&nbsp; <strong>Profile:</strong> {E(result.Profile.ToString())} &nbsp;|&nbsp; <strong>IdP:</strong> {E(result.Idp.ToString())} &nbsp;|&nbsp; <strong>Audited:</strong> {E(result.AuditedAt.ToString("u"))}</div>");
        if (!string.IsNullOrWhiteSpace(result.DiscoverySource))
        {
            sb.AppendLine($"<div class=\"meta\"><strong>Source:</strong> {E(result.DiscoverySource)}</div>");
        }

        if (!string.IsNullOrWhiteSpace(result.PolicyFilePath))
        {
            sb.AppendLine($"<div class=\"meta\"><strong>Policy:</strong> {E(result.PolicyFilePath)}</div>");
        }

        if (!string.IsNullOrWhiteSpace(result.BaselinePath))
        {
            sb.AppendLine($"<div class=\"meta\"><strong>Baseline:</strong> {E(result.BaselinePath)}</div>");
        }

        sb.AppendLine("<div class=\"counts\">");
        sb.AppendLine($"<span class=\"chip\">Critical: {result.Counts.Critical}</span>");
        sb.AppendLine($"<span class=\"chip\">High: {result.Counts.High}</span>");
        sb.AppendLine($"<span class=\"chip\">Medium: {result.Counts.Medium}</span>");
        sb.AppendLine($"<span class=\"chip\">Low: {result.Counts.Low}</span>");
        sb.AppendLine($"<span class=\"chip\">Info: {result.Counts.Info}</span>");
        sb.AppendLine($"<span class=\"chip\">Suppressed: {result.SuppressedFindings.Count}</span>");
        sb.AppendLine("</div></div></div>");

        sb.AppendLine("<h2>Active findings</h2>");
        if (result.Findings.Count == 0)
        {
            sb.AppendLine("<p class=\"empty\">No active findings for the selected profile / suppressions / baseline.</p>");
        }
        else
        {
            foreach (var f in result.Findings)
            {
                AppendFinding(sb, f, suppressed: false);
            }
        }

        if (result.SuppressedFindings.Count > 0)
        {
            sb.AppendLine("<h2>Suppressed / baselined</h2>");
            foreach (var s in result.SuppressedFindings)
            {
                AppendFinding(sb, s.Finding, suppressed: true, reason: s.Reason, source: s.Source.ToString(), until: s.Until?.ToString("yyyy-MM-dd"), ticket: s.Ticket);
            }
        }

        if (result.ExpiredSuppressions.Count > 0)
        {
            sb.AppendLine("<h2>Expired suppressions</h2>");
            sb.AppendLine("<ul class=\"assumptions\">");
            foreach (var e in result.ExpiredSuppressions)
            {
                sb.AppendLine($"<li><strong>{E(e.Id)}</strong> expired {E(e.Until?.ToString("yyyy-MM-dd"))} — {E(e.Reason)}</li>");
            }

            sb.AppendLine("</ul>");
        }

        sb.AppendLine("<h2>Manual verification checklist</h2>");
        sb.AppendLine("<ul class=\"manual\">");
        foreach (var m in result.ManualChecklist)
        {
            sb.AppendLine($"<li><strong>{E(m.Id)} — {E(m.Title)}</strong><br/>{E(m.Guidance)}</li>");
        }

        sb.AppendLine("</ul>");

        sb.AppendLine("<h2>Assumptions</h2>");
        sb.AppendLine("<ul class=\"assumptions\">");
        foreach (var a in result.Assumptions)
        {
            sb.AppendLine($"<li>{E(a)}</li>");
        }

        sb.AppendLine("</ul>");

        sb.AppendLine($"<footer>Generated by AuthGuard {E(result.ToolVersion)}. Defensive configuration audit only — not an exploit scanner.</footer>");
        sb.AppendLine("</div></body></html>");
        return sb.ToString();
    }

    public static void WriteToFile(AuditResult result, string path) =>
        File.WriteAllText(path, Write(result), Encoding.UTF8);

    private static void AppendFinding(
        StringBuilder sb,
        Finding f,
        bool suppressed,
        string? reason = null,
        string? source = null,
        string? until = null,
        string? ticket = null)
    {
        var sev = f.Severity.ToString().ToLowerInvariant();
        var cls = suppressed ? "suppressed" : $"finding {sev}";
        sb.AppendLine($"<article class=\"{cls}\">");
        sb.AppendLine($"<div class=\"sev\">{E(f.Id)} · {E(f.Severity.ToString())}</div>");
        sb.AppendLine($"<h3>{E(f.Title)}</h3>");
        sb.AppendLine($"<p>{E(f.Description)}</p>");
        sb.AppendLine($"<p><span class=\"label\">Evidence:</span> {E(f.Evidence)}</p>");
        sb.AppendLine($"<p><span class=\"label\">Remediation:</span> {E(f.Remediation)}</p>");
        if (suppressed)
        {
            sb.AppendLine($"<p><span class=\"label\">Suppressed via:</span> {E(source)} — {E(reason)}</p>");
            if (!string.IsNullOrWhiteSpace(until))
            {
                sb.AppendLine($"<p><span class=\"label\">Until:</span> {E(until)}</p>");
            }

            if (!string.IsNullOrWhiteSpace(ticket))
            {
                sb.AppendLine($"<p><span class=\"label\">Ticket:</span> {E(ticket)}</p>");
            }
        }

        if (f.References.Count > 0)
        {
            sb.AppendLine("<ul class=\"refs\">");
            foreach (var r in f.References)
            {
                sb.AppendLine($"<li><a href=\"{E(r)}\">{E(r)}</a></li>");
            }

            sb.AppendLine("</ul>");
        }

        sb.AppendLine("</article>");
    }

    private static string E(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
}
