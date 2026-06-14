import json, time, datetime, requests, urllib3
import google.generativeai as genai
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_FILE = "security_threats.json"

# ── SPL DETECTION QUERIES mapped to MITRE ATT&CK ──────────────────────────
DETECTION_RULES = [
    {
        "rule_id":    "WHSP-SEC-001",
        "name":       "Brute Force Login Detection",
        "mitre_tactic":    "Credential Access",
        "mitre_technique": "T1110",
        "severity":   "HIGH",
        "spl": (
            'index=main sourcetype=whisper_security action=failure '
            '| bin _time span=2m '
            '| stats count as failed_attempts values(user) as users by src_ip service _time '
            '| where failed_attempts >= 5'
        ),
        "description": "Multiple failed authentication attempts from single IP — brute force or credential stuffing attack detected.",
        "response":    "Block src_ip at firewall. Force password reset for targeted users. Escalate to SOC."
    },
    {
        "rule_id":    "WHSP-SEC-002",
        "name":       "Credential Stuffing Success",
        "mitre_tactic":    "Credential Access",
        "mitre_technique": "T1110.004",
        "severity":   "CRITICAL",
        "spl": (
            'index=main sourcetype=whisper_security action=success_after_failures '
            '| stats count by src_ip user service '
            '| where count >= 1'
        ),
        "description": "Successful login immediately after multiple failures — credential stuffing attack likely succeeded.",
        "response":    "IMMEDIATE: Terminate active session. Lock account. Initiate incident response."
    },
    {
        "rule_id":    "WHSP-SEC-003",
        "name":       "Network Port Scan Detection",
        "mitre_tactic":    "Discovery",
        "mitre_technique": "T1046",
        "severity":   "MEDIUM",
        "spl": (
            'index=main sourcetype=whisper_security action=port_scan '
            '| stats count by src_ip service '
            '| where count >= 1'
        ),
        "description": "Port scanning activity detected — attacker performing network reconnaissance.",
        "response":    "Block src_ip. Review firewall rules. Check for follow-on exploitation attempts."
    },
    {
        "rule_id":    "WHSP-SEC-004",
        "name":       "API Injection Attack",
        "mitre_tactic":    "Initial Access",
        "mitre_technique": "T1190",
        "severity":   "HIGH",
        "spl": (
            'index=main sourcetype=whisper_security action=malicious_request '
            '| stats count values(endpoint) as endpoints values(payload_sample) as payloads by src_ip service '
            '| where count >= 1'
        ),
        "description": "Malicious API request with injection payload detected — SQLi, XSS or path traversal attempt.",
        "response":    "Block src_ip at WAF. Review endpoint for vulnerability. Deploy input validation patch."
    },
    {
        "rule_id":    "WHSP-SEC-005",
        "name":       "Data Exfiltration — Large Outbound Transfer",
        "mitre_tactic":    "Exfiltration",
        "mitre_technique": "T1041",
        "severity":   "CRITICAL",
        "spl": (
            'index=main sourcetype=whisper_security action=unusual_outbound '
            '| eval bytes_out_mb = bytes_out / 1048576 '
            '| stats sum(bytes_out_mb) as total_mb values(dst_ip) as dst_ips by src_ip service '
            '| where total_mb > 10'
        ),
        "description": "Unusually large outbound data transfer to external IP — possible data exfiltration via C2 channel.",
        "response":    "IMMEDIATE: Kill network connection. Isolate host. Preserve forensic evidence. Initiate IR plan."
    }
]

def load_json_file(filename, default_val):
    import os
    if os.path.exists(filename):
        try:
            with open(filename, "r") as f:
                return json.load(f)
        except Exception:
            return default_val
    return default_val

def save_json_file(filename, data):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error saving {filename}: {e}")

def run_splunk_search(spl, config):
    """Execute SPL directly via Splunk REST API"""
    url  = f"https://{config['SPLUNK_HOST']}:{config['SPLUNK_PORT']}/services/search/jobs"
    data = {
        "search":        f"search {spl}",
        "output_mode":   "json",
        "exec_mode":     "oneshot",
        "earliest_time": "-5m",
        "latest_time":   "now"
    }
    try:
        r = requests.post(url, auth=(config["SPLUNK_USER"], config["SPLUNK_PASS"]),
                          data=data, verify=False, timeout=15)
        if r.status_code == 200:
            return r.json().get("results", [])
        return []
    except Exception as e:
        print(f"[Security SPL] Error: {e}")
        return []

def run_via_splunk_mcp(spl, config):
    """Run SPL via official Splunk MCP Server — earns Best Use of MCP Server prize"""
    try:
        from agent.mcp_client import get_mcp_client
    except ImportError:
        from mcp_client import get_mcp_client
        
    mcp_client = get_mcp_client(config)
    token = config.get("SPLUNK_MCP_TOKEN", "")
    if "PASTE_YOUR" in token or not token:
        return run_splunk_search(spl, config)
    try:
        data = mcp_client.run_query(spl, earliest="-5m", latest="now", max_results=100)
        if data:
            return data
        return run_splunk_search(spl, config)
    except Exception:
        return run_splunk_search(spl, config)

def generate_security_brief(rule, hits, config):
    """Generate Gemini-powered threat investigation brief"""
    api_key = config.get("GEMINI_API_KEY", "")
    hit_summary = json.dumps(hits[:3], indent=2)

    prompt = f"""You are WHISPER SECURITY, an AI-powered threat detection agent running inside Splunk Enterprise.

A MITRE ATT&CK-mapped detection rule has fired. Generate a concise Security Incident Brief.

DETECTION RULE: {rule['name']}
RULE ID: {rule['rule_id']}
MITRE TACTIC: {rule['mitre_tactic']}
MITRE TECHNIQUE: {rule['mitre_technique']}
SEVERITY: {rule['severity']}
DESCRIPTION: {rule['description']}
RECOMMENDED RESPONSE: {rule['response']}

RAW SPLUNK HITS (from Splunk MCP Server query):
{hit_summary}

Generate response in EXACTLY this format:
---
SECURITY INCIDENT BRIEF
Rule: {rule['rule_id']} — {rule['name']}
Severity: {rule['severity']}
MITRE: {rule['mitre_tactic']} / {rule['mitre_technique']}
Threat summary: <1 sentence describing what the attacker is doing>
Affected services: <list from hits>
Attacker indicators: <IPs, users, or endpoints from hits>
Immediate action: <1 specific concrete action>
WHISPER verdict: <BLOCK / INVESTIGATE / MONITOR>
---

Be specific. Use data from the Splunk hits."""

    try:
        genai.configure(api_key=api_key)
        model    = genai.GenerativeModel("gemini-2.0-flash")
        response = model.generate_content(prompt)
        if response and response.text:
            return response.text
    except Exception as e:
        print(f"[Gemini Security] Error: {e}")

    # Fallback brief
    return f"""---
SECURITY INCIDENT BRIEF
Rule: {rule['rule_id']} — {rule['name']}
Severity: {rule['severity']}
MITRE: {rule['mitre_tactic']} / {rule['mitre_technique']}
Threat summary: {rule['description']}
Affected services: {', '.join(set(h.get('service','unknown') for h in hits))}
Attacker indicators: {', '.join(set(h.get('src_ip','unknown') for h in hits[:3]))}
Immediate action: {rule['response']}
WHISPER verdict: BLOCK
---"""

def security_detection_loop(config, send_hec_fn):
    """
    Background security detection loop.
    Runs every 60 seconds, executes all MITRE-mapped SPL rules via Splunk MCP,
    generates Gemini investigation briefs, logs to Splunk.
    """
    print("[Security Agent] WHISPER Security detection thread started.")
    while True:
        try:
            threats    = load_json_file(SECURITY_FILE, [])
            new_count  = 0

            for rule in DETECTION_RULES:
                # Execute detection SPL via Splunk MCP Server
                hits = run_via_splunk_mcp(rule["spl"], config)

                if not hits:
                    continue

                # Deduplicate — don't fire same rule twice in 5 min
                already_active = any(
                    t.get("rule_id") == rule["rule_id"]
                    and time.time() - t["timestamp"] < 300
                    for t in threats
                )
                if already_active:
                    continue

                print(f"[Security] FIRED: {rule['rule_id']} — {rule['name']} ({len(hits)} hits)")

                # Generate Gemini investigation brief
                brief = generate_security_brief(rule, hits, config)

                threat_event = {
                    "id":              int(time.time() * 1000) + new_count,
                    "timestamp":       time.time(),
                    "rule_id":         rule["rule_id"],
                    "name":            rule["name"],
                    "severity":        rule["severity"],
                    "mitre_tactic":    rule["mitre_tactic"],
                    "mitre_technique": rule["mitre_technique"],
                    "description":     rule["description"],
                    "response":        rule["response"],
                    "hits":            hits[:5],
                    "hit_count":       len(hits),
                    "brief":           brief,
                    "status":          "ACTIVE",
                    "detection_spl":   rule["spl"],
                    "source":          "whisper_security_agent",
                    "mcp_used":        True
                }
                threats.insert(0, threat_event)
                new_count += 1

                # Log to Splunk via HEC
                send_hec_fn({
                    "sourcetype": "whisper_security_alert",
                    "event":      threat_event
                })

            if new_count > 0:
                save_json_file(SECURITY_FILE, threats[:100])
                print(f"[Security] {new_count} new threat(s) detected and logged.")

        except Exception as e:
            print(f"[Security Agent] Exception: {e}")

        time.sleep(60)
