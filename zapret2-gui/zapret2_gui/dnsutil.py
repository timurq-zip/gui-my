"""Резолв домена: сначала DoH (чтобы обойти подмену DNS), затем системный резолвер."""
import ipaddress
import socket


def resolve(host: str) -> dict:
    try:
        ipaddress.ip_address(host)
        return {"v4": [host] if ":" not in host else [], "v6": [host] if ":" in host else [], "via": "literal"}
    except ValueError:
        pass
    res = {"v4": [], "v6": [], "via": "none"}
    try:
        import requests
        for t, key, code in (("A", "v4", 1), ("AAAA", "v6", 28)):
            r = requests.get("https://cloudflare-dns.com/dns-query", params={"name": host, "type": t},
                             headers={"accept": "application/dns-json"}, timeout=5)
            res[key] = [a["data"] for a in r.json().get("Answer", []) if a.get("type") == code]
        if res["v4"] or res["v6"]:
            res["via"] = "doh"
            return res
    except Exception:
        pass
    try:
        for fam, key in ((socket.AF_INET, "v4"), (socket.AF_INET6, "v6")):
            try:
                res[key] = sorted({i[4][0] for i in socket.getaddrinfo(host, None, fam, socket.SOCK_DGRAM)})
            except socket.gaierror:
                pass
        res["via"] = "system"
    except Exception:
        pass
    return res
