"""
WHISPER MCP Client
==================
Official Splunk MCP Server client using CORRECT tool names from
https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/1.2/mcp-server-tools

Correct tool names (confirmed from official docs May 2026):
  splunk_run_query          - Execute SPL search
  splunk_get_info           - Splunk instance info
  splunk_get_indexes        - List all indexes
  splunk_get_index_info     - Info on specific index
  splunk_get_metadata       - Metadata about hosts/sources/sourcetypes
  splunk_get_user_info      - Current user info
  splunk_get_user_list      - All users list
  splunk_get_kv_store_collections - KV Store stats
  splunk_get_knowledge_objects    - Saved searches, alerts, macros, etc.
  splunk_run_saved_search   - Run a saved search (beta, April 2026)
  saia_generate_spl         - AI: natural language -> SPL
  saia_explain_spl          - AI: explain SPL in plain English
  saia_optimize_spl         - AI: optimize SPL performance
  saia_ask_splunk_question  - AI: ask anything about Splunk
"""

import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkMCPClient:
    """
    Client for the official Splunk MCP Server at localhost:8089/services/mcp
    Uses bearer token authentication with encrypted MCP tokens.
    Implements ALL 14 official tools for maximum prize eligibility.
    """

    def __init__(self, host: str, token: str, port: int = 8089):
        self.base_url = f"https://{host}:{port}/services/mcp"
        self.token    = token
        self.headers  = {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json"
        }
        self._call_log = []   # tracks every MCP call for demo/audit

    def _call(self, tool_name: str, arguments: dict) -> dict:
        """Core JSON-RPC 2.0 call to Splunk MCP Server."""
        payload = {
            "jsonrpc": "2.0",
            "id":      len(self._call_log) + 1,
            "method":  "tools/call",
            "params":  {"name": tool_name, "arguments": arguments}
        }
        self._call_log.append({"tool": tool_name, "args": arguments})

        try:
            r = requests.post(
                self.base_url, headers=self.headers,
                json=payload, verify=False, timeout=30
            )
            if r.status_code == 200:
                result  = r.json()
                content = result.get("result", {}).get("content", [])
                if content and isinstance(content, list):
                    raw = content[0].get("text", "")
                    try:
                        return {"ok": True, "data": json.loads(raw), "raw": raw}
                    except Exception:
                        return {"ok": True, "data": raw, "raw": raw}
                return {"ok": True, "data": result, "raw": str(result)}
            return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:300]}",
                    "data": None, "raw": ""}
        except Exception as e:
            return {"ok": False, "error": str(e), "data": None, "raw": ""}

    def _extract_list(self, result: dict) -> list:
        if not result.get("ok"):
            return []
        data = result.get("data", [])
        return data if isinstance(data, list) else []

    def _extract_text(self, result: dict) -> str:
        if not result.get("ok"):
            return f"MCP error: {result.get('error', 'unknown')}"
        return str(result.get("raw", result.get("data", "")))

    # ── CORE SPLUNK TOOLS ──────────────────────────────────────────

    def run_query(self, spl: str, earliest: str = "-1h",
                  latest: str = "now", max_results: int = 200) -> list:
        """splunk_run_query — Execute SPL and return results list."""
        result = self._call("splunk_run_query", {
            "query":         spl,
            "earliest_time": earliest,
            "latest_time":   latest,
            "max_results":   max_results
        })
        return self._extract_list(result)

    def run_query_raw(self, spl: str, earliest: str = "-1h",
                      latest: str = "now") -> str:
        """splunk_run_query — returns raw text response."""
        result = self._call("splunk_run_query", {
            "query":         spl,
            "earliest_time": earliest,
            "latest_time":   latest
        })
        return self._extract_text(result)

    def get_info(self) -> dict:
        """splunk_get_info — Splunk instance version, hardware, status."""
        result = self._call("splunk_get_info", {})
        return result.get("data", {}) if result.get("ok") else {}

    def get_indexes(self) -> list:
        """splunk_get_indexes — List all available Splunk indexes."""
        result = self._call("splunk_get_indexes", {})
        return self._extract_list(result)

    def get_index_info(self, index_name: str) -> dict:
        """splunk_get_index_info — Detailed info on a specific index."""
        result = self._call("splunk_get_index_info", {"index": index_name})
        return result.get("data", {}) if result.get("ok") else {}

    def get_metadata(self, index: str = "main",
                     meta_type: str = "sourcetypes") -> list:
        """splunk_get_metadata — Metadata about hosts/sources/sourcetypes."""
        result = self._call("splunk_get_metadata", {
            "index":     index,
            "meta_type": meta_type
        })
        return self._extract_list(result)

    def get_user_info(self) -> dict:
        """splunk_get_user_info — Current authenticated user details."""
        result = self._call("splunk_get_user_info", {})
        return result.get("data", {}) if result.get("ok") else {}

    def get_user_list(self) -> list:
        """splunk_get_user_list — All Splunk users with roles."""
        result = self._call("splunk_get_user_list", {})
        return self._extract_list(result)

    def get_kv_store_collections(self) -> list:
        """splunk_get_kv_store_collections — KV Store size and stats."""
        result = self._call("splunk_get_kv_store_collections", {})
        return self._extract_list(result)

    def get_knowledge_objects(self, object_type: str = "saved_searches",
                               app: str = "search") -> list:
        """
        splunk_get_knowledge_objects — Retrieve knowledge objects.
        Types: saved_searches, alerts, field_extractions, lookups,
               macros, tags, data_models, mltk_models, mltk_algorithms,
               workflow_actions, views, panels, apps
        """
        result = self._call("splunk_get_knowledge_objects", {
            "object_type": object_type,
            "app":         app
        })
        return self._extract_list(result)

    def run_saved_search(self, search_name: str, app: str = "search") -> dict:
        """splunk_run_saved_search — Run an existing saved search (beta)."""
        result = self._call("splunk_run_saved_search", {
            "search_name": search_name,
            "app":         app
        })
        return result.get("data", {}) if result.get("ok") else {}

    # ── SPLUNK AI ASSISTANT TOOLS (saia_) ─────────────────────────

    def generate_spl(self, question: str) -> str:
        """saia_generate_spl — Convert natural language to SPL query."""
        result = self._call("saia_generate_spl", {"question": question})
        return self._extract_text(result)

    def explain_spl(self, spl: str) -> str:
        """saia_explain_spl — Explain what an SPL query does in plain English."""
        result = self._call("saia_explain_spl", {"spl": spl})
        return self._extract_text(result)

    def optimize_spl(self, spl: str) -> str:
        """saia_optimize_spl — Improve SPL performance and efficiency."""
        result = self._call("saia_optimize_spl", {"spl": spl})
        return self._extract_text(result)

    def ask_splunk_question(self, question: str) -> str:
        """saia_ask_splunk_question — Ask anything about Splunk concepts."""
        result = self._call("saia_ask_splunk_question", {"question": question})
        return self._extract_text(result)

    # ── AUDIT / DEMO HELPERS ───────────────────────────────────────

    def get_call_log(self) -> list:
        """Returns log of all MCP tool calls made this session."""
        return self._call_log

    def get_call_summary(self) -> dict:
        """Summary of MCP usage — useful for dashboard display."""
        from collections import Counter
        counts = Counter(c["tool"] for c in self._call_log)
        return {
            "total_calls":   len(self._call_log),
            "tools_used":    dict(counts),
            "unique_tools":  len(counts),
            "endpoint":      self.base_url
        }

    def is_connected(self) -> bool:
        """Quick connectivity check via splunk_get_info."""
        info = self.get_info()
        return bool(info)


# ── SINGLETON FACTORY ──────────────────────────────────────────────

_mcp_instance = None

def get_mcp_client(config: dict) -> SplunkMCPClient:
    """Returns singleton MCP client. Call once, use everywhere."""
    global _mcp_instance
    if _mcp_instance is None:
        _mcp_instance = SplunkMCPClient(
            host  = config.get("SPLUNK_HOST", "localhost"),
            token = config.get("SPLUNK_MCP_TOKEN", ""),
            port  = config.get("SPLUNK_PORT", 8089)
        )
    return _mcp_instance
