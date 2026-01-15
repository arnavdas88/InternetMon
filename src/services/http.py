import requests
from typing import Dict, Any

from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

from src.utils import now_ns

class FixedResolverHTTPAdapter(HTTPAdapter):
    """
    Forces DNS resolution via a fixed IP (8.8.8.8)
    """

    def get_connection(self, url, proxies=None):
        return super().get_connection(url, proxies)


def http_probe(host: str, port: int, path: str = "/") -> Dict[str, Any]:
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}{path}"

    session = requests.Session()
    session.mount("http://", FixedResolverHTTPAdapter())
    session.mount("https://", FixedResolverHTTPAdapter())

    trace = []

    start_total = now_ns()
    try:
        r = session.get(
            url,
            timeout=5,
            allow_redirects=True,
            verify=False,
        )

        for resp in r.history + [r]:
            trace.append({
                "url": resp.url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_bytes": resp.content.decode(),
            })

        end_total = now_ns()

        return {
            "initial_url": url,
            "redirect_chain": trace,
            "final_url": r.url,
            "total_latency_ns": end_total - start_total,
        }

    except Exception as e:
        return {
            "initial_url": url,
            "error": str(e),
            "total_latency_ns": now_ns() - start_total,
        }
