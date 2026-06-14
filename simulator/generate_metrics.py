import requests, json, time, random, math, datetime, os

SPLUNK_HEC_URL = "https://localhost:8088/services/collector/event"

# Load HEC token dynamically from config.json if available
SPLUNK_TOKEN = "your_hec_token"
if os.path.exists("config.json"):
    try:
        with open("config.json", "r") as f:
            SPLUNK_TOKEN = json.load(f).get("SPLUNK_HEC_TOKEN", SPLUNK_TOKEN)
    except Exception:
        pass

VERIFY_SSL     = False                    # Splunk local cert is self-signed

SERVICES = ["payment-api", "auth-service", "database-proxy", "queue-worker"]

def base_metric(t, service_index):
    """Normal baseline with slight hourly rhythm"""
    hour_wave = math.sin(t / 3600 * math.pi) * 10
    return {
        "cpu":     30 + hour_wave + service_index * 5 + random.gauss(0, 2),
        "memory":  45 + hour_wave * 0.5 + service_index * 3 + random.gauss(0, 1.5),
        "latency": 80 + hour_wave * 2 + service_index * 10 + random.gauss(0, 5),
        "errors":  max(0, random.gauss(0.2, 0.3)),
    }

def inject_degradation(metric, phase):
    """Slowly push a service toward failure over ~15 minutes"""
    factor = phase / 30   # 0.0 → 1.0 over 30 ticks = 15 min
    metric["cpu"]     = min(99, metric["cpu"]     + factor * 60)
    metric["latency"] = min(9999, metric["latency"] + factor * 1400)
    metric["errors"]  = metric["errors"] + factor * 15
    return metric

degradation_tick = 0
degrading_service = 0

def send_to_splunk(events):
    batch = ""
    for e in events:
        batch += json.dumps({"time": e["time"], "source": "whisper:metrics",
                             "sourcetype": "whisper_metric", "event": e["data"]})
    r = requests.post(SPLUNK_HEC_URL, headers={"Authorization": f"Splunk {SPLUNK_TOKEN}"},
                      data=batch, verify=VERIFY_SSL, timeout=5)
    if r.status_code != 200:
        print(f"HEC error: {r.text}")

print("WHISPER metric simulator running. Press Ctrl+C to stop.")
cycle = 0

while True:
    now = time.time()
    events = []
    for i, service in enumerate(SERVICES):
        m = base_metric(now, i)
        # inject degradation into one service periodically
        if i == degrading_service and 0 < degradation_tick < 30:
            m = inject_degradation(m, degradation_tick)
        events.append({"time": now, "data": {
            "service": service, "cpu": round(m["cpu"], 1),
            "memory": round(m["memory"], 1), "latency": round(m["latency"], 1),
            "errors": round(m["errors"], 2), "timestamp": datetime.datetime.utcnow().isoformat()
        }})
    send_to_splunk(events)
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Sent metrics for {len(SERVICES)} services")

    cycle += 1
    if cycle % 20 == 0:   # every 10 minutes, start degradation cycle
        degradation_tick = 1
        degrading_service = random.randint(0, len(SERVICES)-1)
        print(f">>> Degradation starting on: {SERVICES[degrading_service]}")
    elif degradation_tick > 0:
        degradation_tick += 1
        if degradation_tick >= 30:
            degradation_tick = 0   # reset after 15 min

    time.sleep(30)
