import socket
from typing import Dict, Any

from src.utils import now_ns

def rdp_fingerprint(host: str, port: int = 3389) -> Dict[str, Any]:
    # Minimal X.224 Connection Request PDU
    x224_cr = bytes.fromhex(
        "03 00 00 13"
        "0e e0 00 00"
		"00 00 00 01"
        "00 08 00 0b"
		"00 00 00"
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    start = now_ns()

    try:
        s.connect((host, port))
        s.sendall(x224_cr)
        resp = s.recv(1024)
        end = now_ns()

        return {
            "connected": True,
            "latency_ns": end - start,
            "response_bytes": len(resp),
            "response_hex": resp.hex(),
        }

    except Exception as e:
        return {
            "connected": False,
            "latency_ns": now_ns() - start,
            "error": str(e),
        }
    finally:
        s.close()
