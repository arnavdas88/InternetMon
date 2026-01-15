import subprocess
from typing import Dict, Any

from src.utils import now_ns

def run_ping(host: str) -> Dict[str, Any]:
    start = now_ns()
    try:
        proc = subprocess.run(
            ["ping", "-c", "3", "-W", "1", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        end = now_ns()
        return {
            "latency_ns": end - start,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except Exception as e:
        end = now_ns()
        return {
            "latency_ns": end - start,
            "error": str(e),
        }
