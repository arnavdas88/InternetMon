import subprocess
from typing import Dict, Any

from src.utils import now_ns


def run_traceroute(host: str) -> Dict[str, Any]:
    start = now_ns()
    try:
        proc = subprocess.run(
            ["traceroute", "-w", "1", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        end = now_ns()
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except Exception as e:
        end = now_ns()
        return {
            "error": str(e),
        }

