import socket
from typing import Dict, Any

from src.utils import now_ns

SOCKET_TIMEOUT = 3.0

def tcp_fingerprint(host: str, port: int) -> Dict[str, Any]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKET_TIMEOUT)

    start = now_ns()
    try:
        s.connect((host, port))
        connected_ns = now_ns()

        local_ip, local_port = s.getsockname()

        banner = b""
        try:
            s.sendall(b"\r\n")
            banner = s.recv(1024)
        except Exception:
            pass

        return {
            "connected": True,
            "connect_latency_ns": connected_ns - start,
            "local_ephemeral_port": local_port,
            "banner_bytes": len(banner),
            "banner_raw": banner.decode(errors="replace"),
        }

    except Exception as e:
        return {
            "connected": False,
            "error": str(e),
            "connect_latency_ns": now_ns() - start,
        }
    finally:
        s.close()
