#!/usr/bin/env python3
"""
WHISPER CLI - Developer Tool
A command-line interface for developers to interact with WHISPER and Splunk.

Usage:
  python whisper_cli.py status
  python whisper_cli.py forecast
  python whisper_cli.py search "index=main | head 5"
  python whisper_cli.py inject database-proxy latency
  python whisper_cli.py slo
  python whisper_cli.py security
  python whisper_cli.py mcp-tools
  python whisper_cli.py help
"""

import sys
import json
import requests

# Safe terminal encoding on Windows to prevent UnicodeEncodeError
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

BASE = "http://localhost:8001"

def call(path, method="GET", data=None):
    try:
        if method == "POST":
            r = requests.post(f"{BASE}{path}", json=data, timeout=30)
        else:
            r = requests.get(f"{BASE}{path}", timeout=30)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def cmd_status():
    print("\n=== WHISPER System Status ===")
    mcp  = call("/api/mcp/status")
    sdk  = call("/api/sdk/status")
    mttd = call("/api/observability/mttd-mttr")
    print(f"MCP Server:      {'CONNECTED' if mcp.get('connected') else 'NOT CONFIGURED'}")
    print(f"Splunk SDK:      {'CONNECTED' if sdk.get('connected') else 'DISCONNECTED'}")
    print(f"MCP Tool Calls:  {mcp.get('mcp_call_summary',{}).get('total_calls', 0)}")
    print(f"Incidents Saved: {mttd.get('incidents_prevented', 0)}")
    print(f"Total Savings:   ${mttd.get('total_savings_usd', 0):,}")
    print(f"MTTD:            {mttd.get('whisper_mttd_minutes')} min  (industry avg: {mttd.get('industry_avg_mttd_minutes')} min)")
    print(f"MTTR:            {mttd.get('whisper_mttr_minutes')} min  (industry avg: {mttd.get('industry_avg_mttr_minutes')} min)")
    print(f"MTTD Improvement:{mttd.get('mttd_improvement')}")
    print(f"MTTR Improvement:{mttd.get('mttr_improvement')}")

def cmd_forecast():
    print("\n=== CDTSM Zero-Shot Forecasts (all services) ===")
    data = call("/api/metrics")
    thresholds = {"cpu": 85, "memory": 88, "latency": 1200, "errors": 8}
    for svc, metrics in data.items():
        print(f"\n  {svc}:")
        for m, vals in metrics.items():
            hist = vals.get("history_values", [])
            curr = hist[-1] if hist else 0
            f15  = vals.get("forecast_15m", 0)
            f60  = vals.get("forecast_60m", 0)
            conf = vals.get("model_confidence", 0)
            flag = " [!] BREACH PREDICTED" if f15 > thresholds.get(m, 9999) else ""
            print(f"    {m:10s}: {curr:7.1f} now -> {f15:7.1f} (15m) -> {f60:7.1f} (60m)  [{conf:.0%}]{flag}")

def cmd_search(query):
    print(f"\n=== Splunk Search via Official MCP Server ===")
    print(f"SPL: {query}\n")
    result = call("/api/developer/mcp-playground", "POST",
                  {"tool": "splunk_run_query", "args": {"query": query}})
    res_data = result.get("result", {})
    if isinstance(res_data, dict):
        data = res_data.get("data", [])
    else:
        data = []
    if isinstance(data, list):
        print(f"Results: {len(data)} events")
        for row in data[:5]:
            print(f"  {json.dumps(row, default=str)[:150]}")
    else:
        print(str(data)[:500])

def cmd_inject(service, metric="cpu"):
    print(f"\n=== Degradation Injector: {service} / {metric} ===")
    result = call("/api/inject", "POST", {"service": service, "metric": metric})
    print(f"  {result.get('message', result)}")
    print(f"  Watch: http://localhost:8001 - CDTSM will forecast breach in ~30s")

def cmd_slo():
    print("\n=== SLO Compliance Report ===")
    data = call("/api/observability/slo")
    overall = data.get("overall_health", "UNKNOWN")
    print(f"  System SLO Health: {overall}\n")
    for svc in data.get("slo_by_service", []):
        service = svc.get("service", "?")
        avail   = svc.get("availability", "?")
        budget  = svc.get("budget_pct", svc.get("error_budget_remaining", "?"))
        met     = svc.get("slo_met", svc.get("slo_overall_met", "?"))
        p99     = svc.get("p99_ms", svc.get("latency_p99_ms", "?"))
        icon    = "[OK]" if str(met).lower() in ["true","1"] else "[X]"
        print(f"  {icon} {service:20s}  Avail: {avail}%  Budget: {budget}%  P99: {p99}ms")

def cmd_security():
    print("\n=== Security Threat Intelligence ===")
    data    = call("/api/security")
    threats = data.get("threats", [])
    active  = data.get("active_count", 0)
    critical = data.get("critical_count", 0)
    print(f"  Active threats: {active}  |  Critical: {critical}\n")
    if not threats:
        print("  [OK] No active threats detected")
        return
    for t in threats[:5]:
        sev    = t.get("severity", "?")
        name   = t.get("name", "?")
        svc    = t.get("service", "?")
        mitre  = t.get("mitre_technique", "?")
        tactic = t.get("mitre_tactic", "?")
        icon   = "[!]" if sev in ["CRITICAL", "HIGH"] else "[-]"
        print(f"  {icon} [{sev:8s}] {name}")
        print(f"           Service: {svc} | MITRE: {tactic}/{mitre}\n")

def cmd_mcp_tools():
    print("\n=== WHISPER MCP Tools (connect via stdio) ===")
    spec  = call("/api/developer/spec")
    tools = spec.get("mcp_server", {}).get("tools", [])
    total = spec.get("mcp_server", {}).get("total_tools", 0)
    print(f"  Total tools available: {total}\n")
    for i, t in enumerate(tools, 1):
        print(f"  {i:2d}. {t}")
    print(f"\n  Connect with: python agent/whisper_agent.py")
    print(f"  Dashboard:    http://localhost:8001")

def cmd_obs():
    print("\n=== Four-Pillar Observability Summary ===")
    data  = call("/api/observability/summary")
    if "error" in data:
        print(f"  Error: Could not retrieve summary ({data['error']})")
        return
    pills = data.get("pillars", {})
    for pillar, info in pills.items():
        count = info.get("count", 0)
        print(f"  {pillar:10s}: {count} data points")
    mttd_data = call("/api/observability/mttd-mttr")
    print(f"\n  MTTD: {mttd_data.get('mttd_improvement')}")
    print(f"  MTTR: {mttd_data.get('mttr_improvement')}")

def cmd_help():
    print("""
+------------------------------------------------------+
|  WHISPER CLI - Splunk Agentic Ops Developer Tool     |
+------------------------------------------------------+

Commands:
  status              MCP connection, SDK, KPIs
  forecast            CDTSM predictions for all services
  search <SPL>        Run SPL via Splunk MCP Server
  inject <svc> <metric>  Inject degradation for demo
  slo                 SLO compliance and error budgets
  security            Active MITRE ATT&CK threats
  mcp-tools           List all 25 WHISPER MCP tools
  observability       Four-pillar summary

Examples:
  python whisper_cli.py status
  python whisper_cli.py forecast
  python whisper_cli.py search "index=main sourcetype=whisper_metric | head 5"
  python whisper_cli.py inject payment-api cpu
  python whisper_cli.py slo
  python whisper_cli.py security
""")

COMMANDS = {
    "status":        cmd_status,
    "forecast":      cmd_forecast,
    "slo":           cmd_slo,
    "security":      cmd_security,
    "mcp-tools":     cmd_mcp_tools,
    "observability": cmd_obs,
    "help":          cmd_help
}

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] in ("help", "--help", "-h"):
        cmd_help()
    elif args[0] == "search":
        if len(args) < 2:
            print("Usage: python whisper_cli.py search \"<SPL query>\"")
        else:
            cmd_search(args[1])
    elif args[0] == "inject":
        if len(args) < 2:
            print("Usage: python whisper_cli.py inject <service> [metric]")
        else:
            cmd_inject(args[1], args[2] if len(args) > 2 else "cpu")
    elif args[0] in COMMANDS:
        COMMANDS[args[0]]()
    else:
        print(f"Unknown command: {args[0]}")
        cmd_help()
