from typing import Dict, Any

from src.services.dns import dns_full_trace
from src.services.http import http_probe
from src.services.ping import run_ping
from src.services.tcp import tcp_fingerprint
from src.services.rdp import rdp_fingerprint
from src.services.traceroute import run_traceroute


from src.utils import now_ns


def scan_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    host = entry["host"]
    port = entry.get("port")

    result = {
        "meta": entry,
        "scan": {},
    }

    if "ping" in entry["scan"]:
        result["scan"]["ping"] = run_ping(host)

    if port:
        result["scan"]["tcp_fingerprint"] = tcp_fingerprint(host, port)

    if "web" in entry["scan"] or "curl" in entry["scan"]:
        path = entry["scan"].get("curl", {}).get("url", "/")
        result["scan"]["http"] = http_probe(host, port or 80, path)
    
    if "rdp" in entry["scan"]:
        result["scan"]["rdp"] = rdp_fingerprint(host, port or 3389)

    if "dns" in entry["scan"]:
        result["scan"]["dns_trace"] = dns_full_trace(host)

    if "traceroute" in entry["scan"]:
        result["scan"]["traceroute"] = run_traceroute(host)

    return result

