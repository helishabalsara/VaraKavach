import sys
import os
import json
import yaml
import importlib
import time
import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print
from collections import defaultdict
from varakavach.internals import system
from varakavach.internals.dpdp_mapper import get_dpdp_info, build_compliance_summary
import ssl

ssl._create_default_https_context = ssl._create_unverified_context

os.system('cls' if os.name == 'nt' else 'clear')
console = Console()


def load_command_module(command):
    try:
        module = importlib.import_module(f"varakavach.commands.{command}")
        return module
    except Exception as e:
        print(f"Command '{command}' not supported. {e}")
        sys.exit(1)


def execute_command(command, args):
    module = load_command_module(command)
    return module.execute(args)


def group_results(args, results):
    grouped_results = defaultdict(list)
    connection = system.get_connection(args)
    for result in results:
        result = system.evaluate_severity(result, connection)
        # Attach DPDP compliance info
        dpdp_info = get_dpdp_info(result.get('pattern_name', ''))
        result['dpdp_category'] = dpdp_info['data_category']
        result['dpdp_section'] = dpdp_info['dpdp_section']
        result['dpdp_obligation'] = dpdp_info['obligation']
        result['cert_in_applicable'] = dpdp_info['cert_in_applicable']
        result['cert_in_rule'] = dpdp_info['cert_in_rule']
        result['penalty_tier'] = dpdp_info['penalty_tier']
        result['max_penalty_inr'] = dpdp_info['max_penalty_inr']
        result['risk_level'] = dpdp_info['risk_level']
        result['remediation_steps'] = dpdp_info['remediation']
        grouped_results[result['data_source']].append(result)
    return grouped_results


def format_slack_message(group, result, records_mini, mention):
    dpdp_section = result.get('dpdp_section', 'N/A')
    penalty = result.get('max_penalty_inr', 'N/A')
    cert_in = result.get('cert_in_rule', 'N/A')
    return (
        f"{mention}\n"
        f"*** DPDP Compliance Alert ***\n"
        f"Data Source: {group.upper()} - {result.get('profile', '')}\n"
        f"Pattern: {result['pattern_name']}\n"
        f"DPDP Section: {dpdp_section}\n"
        f"Max Penalty: {penalty}\n"
        f"CERT-In Rule: {cert_in}\n"
        f"Exposed Count: {len(result['matches'])}\n"
        f"Exposed Values: {records_mini}\n"
    )


def generate_html_report(grouped_results, compliance_summary, output_path="dpdp_compliance_report.html"):
    """Generate a full HTML DPDP compliance report."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = compliance_summary["total_findings"]
    critical = compliance_summary["critical_findings"]
    penalty = compliance_summary["max_penalty_exposure"]
    tier = compliance_summary["highest_penalty_tier"]
    cert_in_required = compliance_summary["cert_in_breach_notification_required"]
    cert_in_hours = compliance_summary["cert_in_notification_window_hours"]
    log_days = compliance_summary["log_retention_days_required"]

    cert_in_badge = (
        f'<span style="background:#dc2626;color:white;padding:4px 10px;border-radius:4px;font-weight:bold;">'
        f'YES – Notify CERT-In within {cert_in_hours}h</span>'
        if cert_in_required
        else '<span style="background:#16a34a;color:white;padding:4px 10px;border-radius:4px;">Not triggered</span>'
    )

    findings_rows = []
    for source, findings in grouped_results.items():
        for f in findings:
            risk_color = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#16a34a"}.get(
                f.get("risk_level", "low"), "#6b7280"
            )
            remediation_html = "<ul>" + "".join(f"<li>{s}</li>" for s in f.get("remediation_steps", [])) + "</ul>"
            findings_rows.append(f"""
            <tr>
                <td><span style="background:{risk_color};color:white;padding:2px 8px;border-radius:3px;font-size:0.8em;">{f.get("risk_level","").upper()}</span></td>
                <td>{source.upper()}</td>
                <td><strong>{f.get("pattern_name","")}</strong></td>
                <td style="font-size:0.8em;color:#6b7280;">{f.get("dpdp_section","")}</td>
                <td style="font-size:0.8em;">{f.get("max_penalty_inr","")}</td>
                <td style="font-size:0.75em;">{f.get("cert_in_rule","")}</td>
                <td style="font-size:0.8em;">{len(f.get("matches",[]))}</td>
                <td style="font-size:0.75em;">{remediation_html}</td>
            </tr>""")

    obligations_html = "<ul>" + "".join(f"<li>{o}</li>" for o in compliance_summary.get("obligation_gaps", [])) + "</ul>"
    sections_html = "<ul>" + "".join(f"<li>{s}</li>" for s in compliance_summary.get("dpdp_act_sections_triggered", [])) + "</ul>"
    cert_in_triggers_html = "<ul>" + "".join(
        f"<li><strong>{t['pattern']}</strong> ({t['source'].upper()}) – {t['rule']}</li>"
        for t in compliance_summary.get("cert_in_breach_triggers", [])
    ) + "</ul>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VaraKavach – Compliance Report</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; margin: 0; background: #f8fafc; color: #1e293b; }}
  header {{ background: linear-gradient(135deg, #0f172a, #1e3a5f); color: white; padding: 32px 40px; }}
  header h1 {{ margin: 0 0 8px; font-size: 1.8em; }}
  header p {{ margin: 0; opacity: 0.7; font-size: 0.9em; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 40px; }}
  .cards {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 32px; }}
  .card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
  .card .value {{ font-size: 2em; font-weight: 700; margin: 4px 0; }}
  .card .label {{ color: #64748b; font-size: 0.85em; }}
  .card.critical {{ border-left: 4px solid #dc2626; }}
  .card.warning {{ border-left: 4px solid #f59e0b; }}
  .card.info {{ border-left: 4px solid #3b82f6; }}
  .card.ok {{ border-left: 4px solid #10b981; }}
  section {{ background: white; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,.08); padding: 24px; margin-bottom: 24px; }}
  section h2 {{ margin-top: 0; font-size: 1.1em; color: #1e293b; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85em; }}
  th {{ background: #f1f5f9; padding: 10px 12px; text-align: left; font-weight: 600; color: #475569; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
  td ul {{ margin: 0; padding-left: 16px; }}
  td li {{ margin-bottom: 4px; }}
  footer {{ text-align: center; color: #94a3b8; font-size: 0.8em; padding: 24px; }}
</style>
</head>
<body>
<header>
  <h1>VaraKavach – Compliance Report</h1>
  <p>India Digital Personal Data Protection Act 2023 | CERT-In §70B | Generated: {now}</p>
</header>
<div class="container">
  <div class="cards">
    <div class="card {'critical' if total > 0 else 'ok'}">
      <div class="label">Total Findings</div>
      <div class="value">{total}</div>
    </div>
    <div class="card {'critical' if critical > 0 else 'ok'}">
      <div class="label">Critical Findings</div>
      <div class="value">{critical}</div>
    </div>
    <div class="card {'critical' if cert_in_required else 'ok'}">
      <div class="label">CERT-In Notification Required</div>
      <div class="value" style="font-size:1em;margin-top:8px;">{cert_in_badge}</div>
    </div>
    <div class="card warning">
      <div class="label">Max Penalty Exposure</div>
      <div class="value" style="font-size:1.4em;">{penalty}</div>
      <div class="label">{tier}</div>
    </div>
  </div>

  <section>
    <h2>DPDP Act Sections Triggered</h2>
    {sections_html}
  </section>

  <section>
    <h2>CERT-In §70B Breach Triggers</h2>
    <p><strong>Log retention required:</strong> {log_days} days | <strong>Breach notification window:</strong> {cert_in_hours} hours</p>
    {cert_in_triggers_html if compliance_summary.get("cert_in_breach_triggers") else "<p style='color:#16a34a;'>No CERT-In breach triggers detected.</p>"}
  </section>

  <section>
    <h2>DPDP Obligation Gaps</h2>
    {obligations_html}
  </section>

  <section>
    <h2>Detailed Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Risk</th><th>Source</th><th>Pattern</th><th>DPDP Section</th>
          <th>Max Penalty</th><th>CERT-In Rule</th><th>Count</th><th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {"".join(findings_rows) if findings_rows else "<tr><td colspan='8' style='text-align:center;color:#16a34a;padding:24px;'>No findings detected.</td></tr>"}
      </tbody>
    </table>
  </section>
</div>
<footer>VaraKavach &mdash; India DPDP Act 2023 Compliance Scanner</footer>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return output_path


def main():
    start_time = time.time()
    args = system.parse_args()
    system.print_banner(args)
    results = []

    if args.command:
        connections = system.get_connection(args)
        data_sources = connections.get('sources', {}).keys()
        commands = [args.command] if args.command != 'all' else data_sources
        for command in commands:
            results.extend(execute_command(command, args))
    else:
        system.print_error(args, "Please provide a command to execute (e.g. fs, s3, all)")
        sys.exit(1)

    grouped_results = group_results(args, results)
    compliance_summary = build_compliance_summary(grouped_results)

    # JSON output
    output_data = {"findings": grouped_results, "dpdp_compliance_summary": compliance_summary}

    if args.json:
        with open(args.json, 'w') as file:
            file.write(json.dumps(output_data, indent=4, default=str))
        system.print_success(args, f"Results saved to {args.json}")

    if args.stdout:
        print(json.dumps(output_data, indent=4, default=str))
        sys.exit(0)

    # HTML report
    if args.report:
        report_path = generate_html_report(grouped_results, compliance_summary)
        system.print_success(args, f"DPDP compliance report saved to: {report_path}")

    # Terminal output
    console.print(Panel(Text("DPDP Compliance Findings", justify="center"), style="bold cyan"))

    # Compliance summary panel
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column("Key", style="bold")
    summary_table.add_column("Value")
    summary_table.add_row("Total Findings", str(compliance_summary["total_findings"]))
    summary_table.add_row("Critical Findings", f"[bold red]{compliance_summary['critical_findings']}[/bold red]")
    summary_table.add_row(
        "CERT-In Breach Notification",
        "[bold red]REQUIRED[/bold red]" if compliance_summary["cert_in_breach_notification_required"] else "[green]Not triggered[/green]"
    )
    summary_table.add_row("Max Penalty Exposure", f"[bold yellow]{compliance_summary['max_penalty_exposure']}[/bold yellow]")
    summary_table.add_row("Penalty Tier", compliance_summary["highest_penalty_tier"])
    summary_table.add_row("Log Retention Required", f"{compliance_summary['log_retention_days_required']} days (CERT-In §70B)")
    console.print(Panel(summary_table, title="[bold cyan]DPDP Act 2023 Compliance Summary[/bold cyan]", border_style="cyan"))

    for group, group_data in grouped_results.items():
        table = Table(
            show_header=True, header_style="bold magenta", show_lines=True,
            title=f"[bold blue]{len(group_data)} findings in {group.upper()}[/bold blue]"
        )
        table.add_column("Risk", width=10)
        table.add_column("Pattern Name")
        table.add_column("DPDP Section")
        table.add_column("Max Penalty")
        table.add_column("CERT-In")
        table.add_column("Count", width=6)
        table.add_column("Location / Sample")

        for result in group_data:
            risk = result.get("risk_level", "low")
            risk_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(risk, "white")
            location = (
                result.get('file_path') or
                result.get('bucket', '') + '/' + result.get('key', '') or
                result.get('host', '') + '/' + result.get('database', '') or
                result.get('sample_text', '')[:40]
            )
            cert_in_text = "[red]YES[/red]" if result.get("cert_in_applicable") else "No"
            table.add_row(
                f"[{risk_style}]{risk.upper()}[/{risk_style}]",
                result.get('pattern_name', ''),
                result.get('dpdp_section', '')[:50] + '...' if len(result.get('dpdp_section','')) > 50 else result.get('dpdp_section',''),
                result.get('max_penalty_inr', ''),
                cert_in_text,
                str(len(result.get('matches', []))),
                str(location)[:60],
            )

            # Notify
            records_mini = ', '.join(result['matches'][:10])
            connection = system.get_connection(args)
            mention = connection.get('notify', {}).get('slack', {}).get('mention', '')
            slack_msg = format_slack_message(group, result, records_mini, mention)
            system.create_jira_ticket(args, result, slack_msg)
            system.SlackNotify(slack_msg, args)

        console.print(table)

    # CERT-In triggers
    if compliance_summary["cert_in_breach_notification_required"]:
        console.print(Panel(
            f"[bold red]CERT-In §70B Breach Notification Required![/bold red]\n"
            f"You must notify CERT-In within [bold]{compliance_summary['cert_in_notification_window_hours']} hours[/bold].\n"
            f"Maintain logs for [bold]{compliance_summary['log_retention_days_required']} days[/bold].\n"
            f"Triggers: {', '.join(t['pattern'] for t in compliance_summary['cert_in_breach_triggers'])}",
            title="[red]CERT-In §70B Alert[/red]",
            border_style="red"
        ))

    end_time = time.time()
    console.print(f"\n[bold green]Scan completed in {end_time - start_time:.2f} seconds.[/bold green]")


if __name__ == '__main__':
    main()
