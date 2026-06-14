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
    """

    def __init__(self, host, port, username, password):
        self.service = client.connect(
            host=host,
            port=port,
            username=username,
            password=password,
            scheme="https"
        )

    def run_search(self, spl: str, earliest: str = "-1h",
                   latest: str = "now") -> list:
        """Run oneshot search via SDK — returns clean result list."""
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
            print(f"[SDK] Search error: {e}")
            return []

    def create_saved_search(self, name: str, spl: str,
                             description: str = "") -> bool:
        """Create a Splunk saved search via SDK."""
        try:
            self.service.saved_searches.create(
                name,
                f"search {spl}",
                description=description,
                is_scheduled=False
            )
            return True
        except Exception as e:
            print(f"[SDK] Saved search creation error: {e}")
            return False

    def list_saved_searches(self) -> list:
        """List all saved searches in Splunk via SDK."""
        try:
            return [{"name": s.name, "query": s["search"]}
                    for s in self.service.saved_searches]
        except Exception as e:
            print(f"[SDK] List saved searches error: {e}")
            return []

    def get_indexes(self) -> list:
        """List Splunk indexes via SDK."""
        try:
            return [{"name": idx.name, "totalEventCount": idx.get("totalEventCount", 0)}
                    for idx in self.service.indexes]
        except Exception as e:
            print(f"[SDK] Indexes error: {e}")
            return []

    def create_alert(self, name: str, spl: str,
                     threshold: int = 1) -> bool:
        """Create a Splunk alert via SDK — triggered when WHISPER detects breach."""
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
            print(f"[SDK] Alert creation error: {e}")
            return False

    def get_server_info(self) -> dict:
        """Get Splunk server info via SDK."""
        try:
            info = self.service.info
            return {
                "version":     info.get("version", "unknown"),
                "server_name": info.get("serverName", "unknown"),
                "os_name":     info.get("os_name", "unknown"),
                "cpu_arch":    info.get("cpu_arch", "unknown")
            }
        except Exception as e:
            print(f"[SDK] Server info error: {e}")
            return {}

    def setup_whisper_saved_searches(self) -> dict:
        """
        Create WHISPER's detection SPL as Splunk saved searches via SDK.
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
        for s in searches_to_create:
            # Skip if already exists
            existing = [ss.name for ss in self.service.saved_searches]
            if s["name"] not in existing:
                ok = self.create_saved_search(s["name"], s["spl"], s["description"])
                results[s["name"]] = "created" if ok else "failed"
            else:
                results[s["name"]] = "already exists"
        return results


def get_sdk_client(config: dict):
    """Factory — returns SDK client or None if connection fails."""
    try:
        return SplunkSDKClient(
            host=config.get("SPLUNK_HOST", "localhost"),
            port=int(config.get("SPLUNK_PORT", 8089)),
            username=config.get("SPLUNK_USER", "admin"),
            password=config.get("SPLUNK_PASS", "")
        )
    except Exception as e:
        print(f"[SDK] Connection failed: {e}")
        return None
