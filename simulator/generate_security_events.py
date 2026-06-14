import requests, json, time, random, datetime, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEC_URL   = "https://localhost:8088/services/collector/event"
HEC_TOKEN = "b81baa89-bc78-49aa-83c1-4d643cd248ea"  # your token

SERVICES  = ["payment-api", "auth-service", "database-proxy", "queue-worker"]
FAKE_IPS  = ["192.168.1."+str(i) for i in range(10,50)]
ATTACK_IPS= ["45.33.32.156","185.220.101.45","103.21.244.0","198.54.117.197"]
USERS     = ["admin","root","sharun7","testuser","api_service","db_admin"]

def send_hec(events):
    batch = ""
    for e in events:
        batch += json.dumps({"time": time.time(), "source": "whisper:security",
                             "sourcetype": "whisper_security", "event": e})
    try:
        requests.post(HEC_URL,
            headers={"Authorization": f"Splunk {HEC_TOKEN}"},
            data=batch, verify=False, timeout=5)
    except Exception as ex:
        print(f"HEC error: {ex}")

def generate_normal_auth():
    """Normal successful login events"""
    return [{
        "event_type":  "authentication",
        "action":      "success",
        "user":        random.choice(USERS[:3]),
        "src_ip":      random.choice(FAKE_IPS),
        "service":     random.choice(SERVICES),
        "timestamp":   datetime.datetime.utcnow().isoformat(),
        "mitre_tactic": None
    }]

def generate_brute_force(target_service):
    """MITRE T1110 — Brute Force: simulate 8-15 failed logins from same IP"""
    attack_ip = random.choice(ATTACK_IPS)
    target_user = random.choice(USERS)
    count = random.randint(8, 15)
    events = []
    for _ in range(count):
        events.append({
            "event_type":     "authentication",
            "action":         "failure",
            "user":           target_user,
            "src_ip":         attack_ip,
            "service":        target_service,
            "timestamp":      datetime.datetime.utcnow().isoformat(),
            "mitre_tactic":   "Credential Access",
            "mitre_technique":"T1110",
            "mitre_name":     "Brute Force",
            "severity":       "HIGH"
        })
    # Sometimes add a success at end (credential stuffing success)
    if random.random() < 0.3:
        events.append({
            "event_type":     "authentication",
            "action":         "success_after_failures",
            "user":           target_user,
            "src_ip":         attack_ip,
            "service":        target_service,
            "timestamp":      datetime.datetime.utcnow().isoformat(),
            "mitre_tactic":   "Credential Access",
            "mitre_technique":"T1110",
            "mitre_name":     "Brute Force — Credential Stuffing Success",
            "severity":       "CRITICAL"
        })
    return events

def generate_port_scan(target_service):
    """MITRE T1046 — Network Service Discovery"""
    attack_ip = random.choice(ATTACK_IPS)
    ports = random.sample(range(1,9999), random.randint(20,50))
    return [{
        "event_type":     "network",
        "action":         "port_scan",
        "src_ip":         attack_ip,
        "ports_scanned":  ports,
        "service":        target_service,
        "timestamp":      datetime.datetime.utcnow().isoformat(),
        "mitre_tactic":   "Discovery",
        "mitre_technique":"T1046",
        "mitre_name":     "Network Service Discovery",
        "severity":       "MEDIUM"
    }]

def generate_data_exfil(target_service):
    """MITRE T1041 — Exfiltration over C2 Channel"""
    return [{
        "event_type":      "network",
        "action":          "unusual_outbound",
        "src_ip":          random.choice(FAKE_IPS),
        "dst_ip":          random.choice(ATTACK_IPS),
        "bytes_out":       random.randint(50000000, 500000000),
        "service":         target_service,
        "timestamp":       datetime.datetime.utcnow().isoformat(),
        "mitre_tactic":    "Exfiltration",
        "mitre_technique": "T1041",
        "mitre_name":      "Exfiltration Over C2 Channel",
        "severity":        "CRITICAL"
    }]

def generate_api_abuse(target_service):
    """MITRE T1190 — Exploit Public-Facing Application"""
    attack_ip = random.choice(ATTACK_IPS)
    payloads = ["'; DROP TABLE users;--", "<script>alert(1)</script>",
                "../../etc/passwd", "{{7*7}}", "admin' OR '1'='1"]
    return [{
        "event_type":      "api",
        "action":          "malicious_request",
        "src_ip":          attack_ip,
        "endpoint":        f"/api/{random.choice(['login','users','admin','config'])}",
        "payload_sample":  random.choice(payloads),
        "service":         target_service,
        "timestamp":       datetime.datetime.utcnow().isoformat(),
        "mitre_tactic":    "Initial Access",
        "mitre_technique": "T1190",
        "mitre_name":      "Exploit Public-Facing Application",
        "severity":        "HIGH"
    }]

print("[Security Simulator] Generating security events into Splunk...")
attack_cycle = 0

while True:
    # Always send normal events
    send_hec(generate_normal_auth())

    attack_cycle += 1
    target = random.choice(SERVICES)

    # Every 4 cycles (~2 min): inject a real attack pattern
    if attack_cycle % 4 == 0:
        attack_type = random.choice(["brute_force","port_scan","api_abuse","data_exfil"])
        if attack_type == "brute_force":
            events = generate_brute_force(target)
            print(f"[Attack] Brute force on {target}")
        elif attack_type == "port_scan":
            events = generate_port_scan(target)
            print(f"[Attack] Port scan on {target}")
        elif attack_type == "api_abuse":
            events = generate_api_abuse(target)
            print(f"[Attack] API abuse on {target}")
        else:
            events = generate_data_exfil(target)
            print(f"[Attack] Data exfiltration on {target}")
        send_hec(events)

    time.sleep(30)
