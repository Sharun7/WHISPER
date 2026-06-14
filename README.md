# 🛡️ WHISPER — Predictive Incident Prevention Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Splunk](https://img.shields.io/badge/Splunk-Enterprise-black.svg)](https://www.splunk.com)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org)
[![Hackathon](https://img.shields.io/badge/Splunk-Agentic%20Ops%20Hackathon-orange.svg)](https://splunk.devpost.com)

> **"Fix it before it breaks."**
> 
> Every monitoring tool alerts you AFTER something breaks. WHISPER predicts
> failures 15–60 minutes BEFORE they occur and automates prevention —
> turning reactive ops into predictive ops, built natively on Splunk Enterprise.

**🎥 Demo Video:** [Watch on YouTube](PASTE_YOUR_VIDEO_LINK_HERE)
**📊 Dashboard:** `http://localhost:8001` (after setup)
**🏆 Submitted to:** Splunk Agentic Ops Hackathon — Observability Track

---

## The Problem

Datadog, Dynatrace, CloudWatch, and standard Splunk dashboards all follow the same pattern:

```
Threshold breached → Alert fires → Human investigates → Fix applied (after damage)
```

WHISPER inverts this:

```
Trend detected → Forecast breach → AI brief generated → One-click prevention (before damage)
```

---

## What WHISPER Does

1. **Ingests live telemetry** for 4 microservices (`payment-api`, `auth-service`, `database-proxy`, `queue-worker`) — metrics, structured logs, distributed traces, and security events — into Splunk Enterprise via HTTP Event Collector (HEC).

2. **Forecasts failures** using a zero-shot forecasting engine (CDTSM-inspired methodology: trend decomposition + seasonal adjustment + 90% confidence intervals). WHISPER actively checks for Splunk Cloud's hosted Cisco Deep Time Series Model and will use it automatically when available, falling back to its local equivalent otherwise.

3. **Generates Pre-Incident Briefs** via Google Gemini 2.0 Flash — root cause hypothesis, risk level, recommended action, confidence score — the moment a forecast crosses a critical threshold.

4. **Detects security threats** via 5 MITRE ATT&CK-mapped detection rules (Brute Force T1110, Credential Stuffing T1110.004, Network Discovery T1046, API Injection T1190, Data Exfiltration T1041), executed as real SPL queries against Splunk via the official Splunk MCP Server.

5. **Tracks full four-pillar observability**: Metrics, Logs, Traces, and SLO/error-budget compliance — with live MTTD/MTTR KPIs comparing WHISPER's predictive detection against industry-average reactive detection.

6. **Provides a developer platform**: a CLI tool, self-documenting OpenAPI spec, reusable SPL query library, and an MCP playground — so other developers can build their own agentic Splunk apps using WHISPER's patterns.

7. **One-click remediation**: operator approves a proposed action, the metric recovers in real time, and the incident is logged to the Prevented Incidents Ledger with estimated cost savings.

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│  Simulators      │────▶│  Splunk Enterprise │────▶│  WHISPER Agent      │
│  - Metrics       │ HEC │  - Indexes         │     │  - CDTSM Forecast   │
│  - Security      │     │  - HEC             │◀───▶│  - Splunk MCP Client│
│  - Logs/Traces   │     │  - MCP Server      │     │  - Splunk SDK       │
│  - SLO           │     │  - REST API        │     │  - Security Engine  │
└─────────────────┘     └──────────────────┘     │  - Gemini Briefs    │
                                                    └──────────┬──────────┘
                                                               │
                                                    ┌──────────▼──────────┐
                                                    │  WHISPER Dashboard   │
                                                    │  - Live metrics      │
                                                    │  - Forecast curves   │
                                                    │  - Security threats  │
                                                    │  - Observability KPIs│
                                                    │  - Co-Pilot Approvals│
                                                    └─────────────────────┘
```

See `architecture.png` for the full diagram.

---

## Splunk AI Capabilities Used

| Capability | How WHISPER uses it |
|---|---|
| **Splunk MCP Server** (`localhost:8089/services/mcp`) | All 14 official tools: `splunk_run_query`, `splunk_get_info`, `splunk_get_indexes`, `splunk_get_index_info`, `splunk_get_metadata`, `splunk_get_user_info`, `splunk_get_user_list`, `splunk_get_kv_store_collections`, `splunk_get_knowledge_objects`, `splunk_run_saved_search`, `saia_generate_spl`, `saia_explain_spl`, `saia_optimize_spl`, `saia_ask_splunk_question` |
| **Splunk Hosted Models (AI Toolkit)** | WHISPER actively probes for Splunk Cloud's Cisco Deep Time Series Model (`apply CDTSM`) via `/api/hosted-models/status`. When unavailable (on-prem Enterprise), falls back to a local zero-shot forecasting engine implementing the same trend + seasonality + confidence-interval methodology |
| **Splunk Python SDK** (`splunklib`) | Creates and manages saved searches as Splunk knowledge objects, retrieves server info, lists indexes |
| **HTTP Event Collector (HEC)** | Real-time ingestion of metrics, logs, traces, SLO data, security events, and alerts across 8 sourcetypes |
| **Splunk App Framework** | Full app structure (`app.conf`, `inputs.conf`, custom dashboard) deployable to `$SPLUNK_HOME/etc/apps` |
| **Google Gemini 2.0 Flash** | Natural language Pre-Incident Brief and Security Incident Brief generation |

---

## Directory Structure

```
WHISPER/
├── agent/
│   ├── whisper_agent.py        # FastAPI server + forecasting + Gemini + FastMCP (25 tools)
│   ├── security_agent.py       # MITRE ATT&CK detection loop
│   ├── mcp_client.py           # Official Splunk MCP Server client (14 tools)
│   └── splunk_sdk_client.py    # Official Splunk Python SDK client
├── simulator/
│   ├── generate_metrics.py            # CPU/memory/latency/error simulator
│   ├── generate_security_events.py    # MITRE ATT&CK attack simulator
│   └── observability_upgrade.py       # Logs/traces/SLO/alerts simulator
├── splunk_app/whisper/
│   ├── default/{app.conf, inputs.conf}
│   └── appserver/static/dashboard.html
├── run_whisper.py               # One-command launcher for all components
├── whisper_cli.py                # Developer CLI tool
├── architecture.png
├── README.md
└── LICENSE (MIT)
```

---

## Setup & Run

### Prerequisites
```bash
pip install requests google-generativeai fastapi uvicorn mcp splunk-sdk
```

### Configure Splunk
1. Install Splunk Enterprise + Developer License
2. Enable HTTP Event Collector, create a token, copy into `config.json`
3. Install the official **Splunk MCP Server** app from Splunkbase, create an encrypted MCP token, copy into `config.json`

### Run everything with one command
```bash
python run_whisper.py
```

This starts all 4 components (metrics, security, observability simulators + WHISPER agent) with health checks and unified logging.

### Open the dashboard
```
http://localhost:8001
```

### Use the developer CLI
```bash
python whisper_cli.py status        # MCP/SDK connection + KPIs
python whisper_cli.py forecast      # Live CDTSM-equivalent predictions
python whisper_cli.py slo            # SLO compliance report
python whisper_cli.py security       # MITRE ATT&CK threat summary
python whisper_cli.py mcp-tools      # List all 25 WHISPER MCP tools
python whisper_cli.py inject database-proxy latency   # Trigger a demo degradation
```

---

## Demo Walkthrough

1. Open `http://localhost:8001` — observe all 4 services healthy, live metric charts
2. Click a degradation injector button (e.g. "Spike Slow Queries" on `database-proxy`)
3. Within ~30 seconds, the forecast curve climbs toward the critical threshold
4. A **Pre-Incident Brief** appears in Co-Pilot Approvals, generated by Gemini using context from Splunk MCP queries
5. Click **Execute Remediation** — the metric recovers in real time
6. **Prevented Incidents Ledger** updates with cost savings; **Observability KPIs** panel shows MTTD/MTTR vs industry average

---

## Track

**Observability** (also targeting Best Use of Splunk MCP Server, Best Use of Splunk Developer Tools, Best Use of Splunk Hosted Models, Best of Platform & Developer Experience, Best of Security)

---

## Team

Sharun — MSc Data Analytics, Marthoma College (MG University)

---

## License

MIT — see `LICENSE`
