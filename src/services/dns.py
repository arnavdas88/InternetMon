from typing import List, Dict, Any
import dns.name
import dns.message
import dns.query
import dns.rdatatype
import dns.rdataclass
import dns.dnssec
import dns.resolver
import dns.exception
import dns.flags
import dns.rrset
import dns.rcode
import time

from src.utils import now_ns

# Root server IPs (IPv4 only for simplicity)
ROOT_SERVERS = [
    "198.41.0.4",     # a.root-servers.net
    "199.9.14.201",   # b.root-servers.net
    "192.33.4.12",    # c.root-servers.net
    "199.7.91.13",    # d.root-servers.net
    "192.203.230.10", # e.root-servers.net
]

def resolve_via_google(domain: str, rdtype: str = "A") -> Dict[str, Any]:
    start = now_ns()
    try:
        q = dns.message.make_query(domain, rdtype, want_dnssec=True)
        r = dns.query.udp(q, "8.8.8.8", timeout=3)
        end = now_ns()

        ips = []
        for rrset in r.answer:
            if rrset.rdtype == dns.rdatatype.A:
                for rdata in rrset:
                    ips.append(rdata.address)

        return {
            "latency_ns": end - start,
            "rcode": dns.rcode.to_text(r.rcode()),
            "flags": int(r.flags),
            "ips": ips,
            "raw_answer": [str(rr) for rr in r.answer],
        }
    except Exception as e:
        return {
            "latency_ns": now_ns() - start,
            "error": str(e),
        }

def send_query(
    qname: dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    server: str,
    want_dnssec: bool = True,
    timeout: float = 3.0,
):
    
    msg = dns.message.make_query(
        qname,
        rdtype,
        want_dnssec=want_dnssec,
    )
    msg.flags &= ~dns.flags.RD  # iterative
    return dns.query.udp(msg, server, timeout=timeout)

def extract_rrsets(response):
    rrsets = []
    for section_name, section in [
        ("answer", response.answer),
        ("authority", response.authority),
        ("additional", response.additional),
    ]:
        for rrset in section:
            rrsets.append({
                "section": section_name,
                "name": rrset.name.to_text(),
                "type": dns.rdatatype.to_text(rrset.rdtype),
                "ttl": rrset.ttl,
                "records": [r.to_text() for r in rrset],
            })
    return rrsets

def get_ns_ips(response):
    """Extract glue IPs or fallback to resolver lookup."""
    ips = []

    for rrset in response.additional:
        if rrset.rdtype == dns.rdatatype.A:
            for r in rrset:
                ips.append(r.address)

    if ips:
        return ips

    # No glue → resolve NS names
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for r in rrset:
                try:
                    ans = dns.resolver.resolve(r.target, "A")
                    for ip in ans:
                        ips.append(ip.address)
                except Exception:
                    pass

    return ips

def validate_dnssec(rrsets, dnskey_rrset):
    """Best-effort DNSSEC validation"""
    try:
        for rr in rrsets:
            if rr.rdtype == dns.rdatatype.RRSIG:
                covered = rr.covers()
                dns.dnssec.validate(rrsets, rr, {dnskey_rrset.name: dnskey_rrset})
        return True, None
    except Exception as e:
        return False, str(e)

def dns_full_trace(domain: str) -> List[Dict[str, Any]]:
    trace: List[Dict[str, Any]] = []

    name = dns.name.from_text(domain)
    current_ns_ips = ROOT_SERVERS[:]

    for depth in range(2, len(name.labels) + 1):
        qname = name.split(depth)[1]
        qname_text = qname.to_text()

        step_info: Dict[str, Any] = {
            "qname": qname_text,
            "queried_at": time.time(),
            "servers": current_ns_ips,
            "responses": [],
            "dnssec": {
                "dnskey_present": False,
                "rrsig_present": False,
                "validated": None,
                "error": None,
            },
        }

        response = None
        server_used = None

        for server in current_ns_ips:
            try:
                response = send_query(qname, dns.rdatatype.NS, server)
                server_used = server
                break
            except Exception:
                continue

        if response is None:
            step_info["error"] = "All servers unreachable"
            trace.append(step_info)
            break

        step_info["server_used"] = server_used
        step_info["flags"] = dns.flags.to_text(response.flags)
        step_info["rcode"] = dns.rcode.to_text(response.rcode())
        step_info["rrsets"] = extract_rrsets(response)

        # DNSSEC detection
        dnskey_rrset = None
        rrsig_rrsets = []

        for rrset in response.answer + response.authority:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                dnskey_rrset = rrset
                step_info["dnssec"]["dnskey_present"] = True
            if rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig_rrsets.append(rrset)
                step_info["dnssec"]["rrsig_present"] = True

        if dnskey_rrset and rrsig_rrsets:
            valid, err = validate_dnssec(rrsig_rrsets, dnskey_rrset)
            step_info["dnssec"]["validated"] = valid
            step_info["dnssec"]["error"] = err

        trace.append(step_info)

        # Prepare next hop
        next_ips = get_ns_ips(response)
        if not next_ips:
            break
        current_ns_ips = next_ips

    return trace
