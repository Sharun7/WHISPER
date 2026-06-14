import splunklib.client as client
import splunklib.results as results_reader

class SplunkSDKClient:
    """
    Official Splunk Enterprise SDK for Python (splunklib)
    Covers capabilities the MCP client does not:
    - Saved search creation and management
    - Search job lifecycle management  
    - Alert creation
    - Index management
    - Real-time streaming results
    - Re-authentication on session expiration
    """

    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.service = None
        self._last_err = None
        self.connect()

    def connect(self):
        try:
            self.service = client.connect(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                scheme="https"
            )
            self._last_err = None
        except Exception as e:
            err_str = str(e)
            if err_str != self._last_err:
                print(f"[SDK] Connection failed: {err_str}")
                self._last_err = err_str

    def _handle_error(self, method_name: str, e: Exception) -> bool:
        """Helper to handle errors, reconnect on session expiration, and avoid log spam."""
        err_str = str(e)
        # Check if session has expired or requires login
        if "Session is not logged in" in err_str or "login" in err_str.lower():
            if self._last_err != "Session expired":
                print(f"[SDK] Session expired in {method_name}. Re-authenticating...")
                self._last_err = "Session expired"
            self.connect()
            return True  # indicates it attempted to reconnect
        
        if err_str != self._last_err:
            print(f"[SDK] {method_name} error: {err_str}")
            self._last_err = err_str
        return False

    def run_search(self, spl: str, earliest: str = "-1h",
                   latest: str = "now") -> list:
        """Run oneshot search via SDK — returns clean result list."""
        for attempt in range(2):
            if not self.service:
                self.connect()
                if not self.service:
                    return []
            try:
                job = self.service.jobs.oneshot(
                    f"search {spl}",
                    earliest_time=earliest,
                    latest_time=latest,
                    output_mode="json"
                )
                rows = []
                for result in results_reader.JSONResultsReader(job):
                    if isinstance(result, dict):
                        rows.append(result)
                return rows
            except Exception as e:
                reconnected = self._handle_error("run_search", e)
                if not reconnected:
                    break
        return []

    def create_saved_search(self, name: str, spl: str,
                             description: str = "") -> bool:
        """Create a Splunk saved search via SDK."""
        for attempt in range(2):
            if not self.service:
                self.connect()
                if not self.service:
                    return False
            try:
                self.service.saved_searches.create(
                    name,
                    f"search {spl}",
                    description=description,
                    is_scheduled=False
                )
                return True
            except Exception as e:
                reconnected = self._handle_error("create_saved_search", e)
                if not reconnected:
                    break
        return False

    def list_saved_searches(self) -> list:
        """List all saved searches in Splunk via SDK."""
        for attempt in range(2):
            if not self.service:
                self.connect()
                if not self.service:
                    return []
            try:
                return [{"name": s.name, "query": s["search"]}
                        for s in self.service.saved_searches]
            except Exception as e:
                reconnected = self._handle_error("list_saved_searches", e)
                if not reconnected:
                    break
        return []

    def get_indexes(self) -> list:
        """List Splunk indexes via SDK."""
        for attempt in range(2):
            if not self.service:
                self.connect()
                if not self.service:
                    return []
            try:
                # Deduplicate output error by avoiding print if EAI totalEventCount fails
                return [{"name": idx.name, "totalEventCount": idx.get("totalEventCount", 0)}
                        for idx in self.service.indexes]
            except Exception as e:
                reconnected = self._handle_error("get_indexes", e)
                if not reconnected:
                    break
        return []

    def create_alert(self, name: str, spl: str,
                      threshold: int = 1) -> bool:
        """Create a Splunk alert via SDK — triggered when WHISPER detects breach."""
        for attempt in range(2):
            if not self.service:
                self.connect()
                if not self.service:
                    return False
            try:
                self.service.saved_searches.create(
                    name,
                    f"search {spl}",
                    alert_type="number of events",
                    alert_comparator="greater than",
                    alert_threshold=str(threshold),
                    actions="email",
                    alert_condition=f"search count > {threshold}"
                )
                return True
            except Exception as e:
                reconnected = self._handle_error("create_alert", e)
                if not reconnected:
                    break
        return False

    def get_server_info(self) -> dict:
        """Get Splunk server info via SDK."""
        for attempt in range(2):
            if not self.service:
                self.connect()
                if not self.service:
                    return {}
            try:
                info = self.service.info
                return {
                    "version":     info.get("version", "unknown"),
                    "server_name": info.get("serverName", "unknown"),
                    "os_name":     info.get("os_name", "unknown"),
                    "cpu_arch":    info.get("cpu_arch", "unknown")
                }
            except Exception as e:
                reconnected = self._handle_error("get_server_info", e)
                if not reconnected:
                    break
        return {}

    def setup_whisper_saved_searches(self) -> dict:
        """
        Create WHISPER's detection queries as Splunk saved searches via SDK.
        This demonstrates deep SDK integration — saving reusable searches
        directly into Splunk's knowledge object layer.
        """
        searches_to_create = [
            {
                "name":        "WHISPER - CPU Breach Forecast",
                "spl":         "index=main sourcetype=whisper_metric | stats avg(cpu) as avg_cpu by service | where avg_cpu > 70",
                "description": "WHISPER predictive CPU monitoring — flags services trending toward breach"
            },
            {
                "name":        "WHISPER - Latency Spike Detection",
                "spl":         "index=main sourcetype=whisper_metric | stats avg(latency) as avg_lat by service | where avg_lat > 800",
                "description": "WHISPER latency anomaly — services approaching 1200ms critical threshold"
            },
            {
                "name":        "WHISPER - Security Auth Failures",
                "spl":         "index=main sourcetype=whisper_security action=failure | stats count by src_ip service | where count > 5",
                "description": "WHISPER security — brute force detection across microservices"
            },
            {
                "name":        "WHISPER - Prevented Incidents Summary",
                "spl":         "index=main sourcetype=whisper_alert status=PREVENTED | stats count sum(savings) as total_saved by service",
                "description": "WHISPER ROI dashboard — incidents prevented and cost savings"
            }
        ]
        results = {}
        if not self.service:
            self.connect()
            if not self.service:
                return {"error": "SDK connection unavailable"}

        try:
            existing = [ss.name for ss in self.service.saved_searches]
        except Exception as e:
            self._handle_error("setup_whisper_saved_searches", e)
            return {"error": str(e)}

        for s in searches_to_create:
            if s["name"] not in existing:
                ok = self.create_saved_search(s["name"], s["spl"], s["description"])
                results[s["name"]] = "created" if ok else "failed"
            else:
                results[s["name"]] = "already exists"
        return results


def get_sdk_client(config: dict):
    """Factory — returns SDK client or None if connection fails on startup."""
    try:
        client_instance = SplunkSDKClient(
            host=config.get("SPLUNK_HOST", "localhost"),
            port=int(config.get("SPLUNK_PORT", 8089)),
            username=config.get("SPLUNK_USER", "admin"),
            password=config.get("SPLUNK_PASS", "")
        )
        return client_instance
    except Exception as e:
        print(f"[SDK] Initialization failed: {e}")
        return None
