"""Генерация правил nftables по образцу из README zapret2 (queue + mark 0x40000000 + notrack)."""
from __future__ import annotations
import re

TABLE = "zapret2gui"
MARK = "0x40000000"
_IFACE = re.compile(r"^[A-Za-z0-9_.@:-]{1,15}$")


def _set(ports: str) -> str:
    return ", ".join(ports.replace(" ", "").split(","))


def _rules(proto, ports, qnum, limit, out, addrs, iface):
    base = [f"meta mark & {MARK} == 0"]
    if iface:
        base.append(f'{"oifname" if out else "iifname"} "{iface}"')
    tail = [f"{proto} {'dport' if out else 'sport'} {{ {_set(ports)} }}",
            f"ct {'original' if out else 'reply'} packets 1-{limit}",
            f"queue num {qnum} bypass"]
    side = "daddr" if out else "saddr"
    v4 = [a for a in addrs if ":" not in a]
    v6 = [a for a in addrs if ":" in a]
    if not addrs:
        return [" ".join(base + tail)]
    res = []
    if v4:
        res.append(" ".join(base + [f"ip {side} {{ {', '.join(v4)} }}"] + tail))
    if v6:
        res.append(" ".join(base + [f"ip6 {side} {{ {', '.join(v6)} }}"] + tail))
    return res


def build_ruleset(tcp_ports: str, udp_ports: str, qnum: int, packet_limit: int = 12,
                  replies: bool = True, iface: str = "", addrs=(), table: str = TABLE) -> str:
    if not tcp_ports and not udp_ports:
        raise ValueError("Нечего перехватывать: ни у одного активного профиля нет --filter-tcp/--filter-udp")
    if iface and not _IFACE.match(iface):
        raise ValueError("Некорректное имя интерфейса")
    post, pre = [], []
    for proto, ports in (("tcp", tcp_ports), ("udp", udp_ports)):
        if ports:
            post += _rules(proto, ports, qnum, packet_limit, True, addrs, iface)
            if replies:
                pre += _rules(proto, ports, qnum, packet_limit, False, addrs, iface)
    lines = [f"add table inet {table}", f"delete table inet {table}", f"table inet {table} {{",
             "  chain predefrag {", "    type filter hook output priority -401; policy accept;",
             f"    meta mark & {MARK} != 0 notrack", "  }",
             "  chain post {", "    type filter hook postrouting priority 101; policy accept;"]
    lines += [f"    {r}" for r in post] + ["  }"]
    if pre:
        lines += ["  chain pre {", "    type filter hook prerouting priority -101; policy accept;"]
        lines += [f"    {r}" for r in pre] + ["  }"]
    lines.append("}")
    return "\n".join(lines) + "\n"
