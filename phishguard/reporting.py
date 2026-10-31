"""Reporting System - Generates JSON, CSV, and Neo-Brutalist HTML reports."""

import json
import csv
import io
import html
from typing import List
from .models import AnalysisResult, BatchAnalysisSummary


class ReportGenerator:
    """Generates structured, clean exports in multiple standard formats."""

    @classmethod
    def to_json(cls, result: AnalysisResult) -> str:
        return json.dumps(result.to_dict(), indent=2)

    @classmethod
    def batch_to_json(cls, summary: BatchAnalysisSummary) -> str:
        return json.dumps(summary.to_dict(), indent=2)

    @classmethod
    def to_csv(cls, results: List[AnalysisResult]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Analysis ID",
            "Timestamp",
            "Sanitized URL",
            "Indicator Count",
            "Educational Classification",
            "Detected Checks"
        ])
        for r in results:
            detected_str = "; ".join([f.name for f in r.findings if f.detected]) or "None"
            writer.writerow([
                r.analysis_id,
                r.timestamp,
                r.sanitized_url,
                r.indicator_count,
                r.classification.value,
                detected_str
            ])
        return output.getvalue()

    @classmethod
    def to_html(cls, result: AnalysisResult) -> str:
        """Generates a standalone, stylish Neo-Brutalist HTML report."""
        badge_bg = (
            "#A9D9B5" if result.indicator_count == 0 
            else ("#F4C84A" if result.indicator_count <= 2 else "#F07858")
        )

        findings_rows = ""
        for f in result.findings:
            status_badge = (
                '<span style="background:#F07858;color:#171717;border:2px solid #171717;padding:3px 8px;font-weight:700;display:inline-block;">FLAGGED</span>'
                if f.detected else
                '<span style="background:#A9D9B5;color:#171717;border:2px solid #171717;padding:3px 8px;font-weight:700;display:inline-block;">CLEAR</span>'
            )
            evidence_line = f'<div style="font-family:IBM Plex Mono, monospace;font-size:12px;margin-top:6px;background:#f0ece1;padding:4px 8px;border:1px solid #171717;">{html.escape(f.evidence)}</div>' if f.evidence else ""

            findings_rows += f"""
            <tr style="border-bottom:2px solid #171717;">
              <td style="padding:12px;font-weight:700;border-right:2px solid #171717;">{html.escape(f.name)}</td>
              <td style="padding:12px;border-right:2px solid #171717;text-align:center;">{status_badge}</td>
              <td style="padding:12px;border-right:2px solid #171717;">
                <div>{html.escape(f.why_it_matters)}</div>
                {evidence_line}
              </td>
              <td style="padding:12px;border-right:2px solid #171717;font-size:13px;color:#444;">{html.escape(f.limitations)}</td>
              <td style="padding:12px;font-size:12px;font-family:IBM Plex Mono, monospace;">{html.escape(f.agent_name)}</td>
            </tr>
            """

        steps_list = "".join(f"<li style='margin-bottom:8px;'>{html.escape(s)}</li>" for s in result.safe_next_steps)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PhishGuard Security Report — {html.escape(result.analysis_id)}</title>
  <style>
    body {{
      background: #F7F3E9;
      color: #171717;
      font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 40px 20px;
    }}
    .container {{
      max-width: 900px;
      margin: 0 auto;
      background: #FFFFFF;
      border: 3px solid #171717;
      box-shadow: 6px 6px 0px #171717;
      padding: 32px;
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 3px solid #171717;
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    .brand {{
      font-family: 'Space Grotesk', sans-serif;
      font-size: 28px;
      font-weight: 800;
      letter-spacing: -1px;
    }}
    .badge {{
      display: inline-block;
      padding: 6px 14px;
      border: 2px solid #171717;
      box-shadow: 3px 3px 0px #171717;
      font-weight: 800;
      font-size: 14px;
      text-transform: uppercase;
    }}
    .mono-box {{
      font-family: 'IBM Plex Mono', monospace;
      background: #F7F3E9;
      border: 2px solid #171717;
      padding: 12px 16px;
      font-size: 14px;
      word-break: break-all;
      margin: 16px 0;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      border: 2px solid #171717;
      margin: 24px 0;
    }}
    th {{
      background: #3155D9;
      color: #FFFFFF;
      text-align: left;
      padding: 12px;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-right: 2px solid #171717;
    }}
    .alert-box {{
      background: #F4C84A;
      border: 2px solid #171717;
      box-shadow: 4px 4px 0 #171717;
      padding: 16px;
      margin: 24px 0;
      font-size: 14px;
      line-height: 1.5;
    }}
    .footer {{
      margin-top: 32px;
      border-top: 2px solid #171717;
      padding-top: 16px;
      font-size: 12px;
      color: #666;
      display: flex;
      justify-content: space-between;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div class="brand">PHISHGUARD // AUDIT REPORT</div>
        <div style="font-size:13px;color:#555;margin-top:4px;">Defensive Cybersecurity Education & Awareness</div>
      </div>
      <div class="badge" style="background:{badge_bg};">
        {html.escape(result.classification.value)}
      </div>
    </div>

    <div><strong>Target URL (Inspected Locally):</strong></div>
    <div class="mono-box">{html.escape(result.url)}</div>

    <div style="display:flex;gap:20px;margin-bottom:20px;font-size:14px;">
      <div><strong>Analysis ID:</strong> <span style="font-family:IBM Plex Mono, monospace;">{html.escape(result.analysis_id)}</span></div>
      <div><strong>Timestamp:</strong> {html.escape(result.timestamp)}</div>
      <div><strong>Indicators Detected:</strong> <strong>{result.indicator_count} / 6</strong></div>
    </div>

    <div class="alert-box">
      <strong>Important Educational Disclaimer:</strong><br>
      {html.escape(result.limitations)}
    </div>

    <h3>Detailed Heuristic Findings</h3>
    <table>
      <thead>
        <tr>
          <th>Check Name</th>
          <th style="text-align:center;">Result</th>
          <th>Significance & Evidence</th>
          <th>Limitations</th>
          <th>Responsible Agent</th>
        </tr>
      </thead>
      <tbody>
        {findings_rows}
      </tbody>
    </table>

    <div style="background:#FFFFFF;border:2px solid #171717;box-shadow:4px 4px 0 #171717;padding:16px;margin:24px 0;">
      <h4 style="margin-top:0;">Recommended Next Steps:</h4>
      <ul style="padding-left:20px;margin-bottom:0;">
        {steps_list}
      </ul>
    </div>

    <div class="footer">
      <div>Generated locally by PhishGuard Platform. Zero network requests made.</div>
      <div>EWB Cybersecurity Mini Project Workbook Compliant</div>
    </div>
  </div>
</body>
</html>"""

