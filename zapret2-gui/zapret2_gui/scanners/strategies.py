"""Генераторы кандидатов-стратегий. Каждый кандидат — обычный Profile (его можно применить в GUI одной кнопкой)."""
from __future__ import annotations
import itertools
import random
from dataclasses import dataclass
from ..models import Profile, Step, ZERO_BLOB_16

PAYLOAD_BY_L7 = {"quic": "quic_initial", "stun": "stun", "wireguard": "wireguard_initiation"}


@dataclass
class Candidate:
    name: str
    profile: Profile
    meta: dict


def parse_ports(spec: str) -> list:
    out = []
    for t in str(spec).replace(" ", "").split(","):
        if not t:
            continue
        lo, _, hi = t.partition("-")
        out += list(range(int(lo), int(hi or lo) + 1))
    return out


def _fool_params(f: str) -> list:
    res = []
    for tok in f.split(":") if f else []:
        k, _, v = tok.partition("=")
        res.append([k, v])
    return res


def _rep_values(space: dict, dmin, dmax, dstep=1) -> list:
    r = space.get("repeats", {})
    return list(range(int(r.get("min", dmin)), int(r.get("max", dmax)) + 1, int(r.get("step", dstep))))


def _finish(cands: list, cfg: dict) -> list:
    cap = int(cfg.get("limits", {}).get("max_candidates", 60))
    return cands[:cap]


def gen_udp(cfg: dict) -> list:
    l7 = cfg.get("l7", "quic")
    port = int(cfg["target"].get("port", 443))
    space = cfg.get("space", {})
    blobs = space.get("blobs") or (["fake_default_quic", ZERO_BLOB_16] if l7 == "quic" else [ZERO_BLOB_16])
    fools = space.get("fooling", [""])
    out = []
    for r, b, f in itertools.product(_rep_values(space, 2, 11, 1), blobs, fools):
        step = Step("fake", [["blob", b], ["repeats", str(r)]] + _fool_params(f), payload=PAYLOAD_BY_L7.get(l7, "all"))
        prof = Profile(name=f"scan-udp-{l7}", filter_udp=str(port), filter_l7=[l7], steps=[step])
        out.append(Candidate(f"fake blob={b[:24]} repeats={r}" + (f" +{f}" if f else ""), prof,
                             {"repeats": r, "blob": b, "fooling": f}))
    out.sort(key=lambda c: (c.meta["repeats"], c.meta["fooling"] != ""))
    return _finish(out, cfg)


def gen_game(cfg: dict) -> list:
    ports = str(cfg["target"].get("ports", "")).replace(" ", "")
    space = cfg.get("space", {})
    blobs = space.get("blobs") or [ZERO_BLOB_16, "0x00000000", "0x" + "00" * 64]
    fools = space.get("fooling", [""])
    out = []
    for r, b, f in itertools.product(_rep_values(space, 1, 6, 1), blobs, fools):
        step = Step("fake", [["blob", b], ["repeats", str(r)], ["payload", "all"]] + _fool_params(f), payload="all")
        out.append(Candidate(f"game fake blob={b[:24]} repeats={r}" + (f" +{f}" if f else ""),
                             Profile(name="scan-game", filter_udp=ports, steps=[step]),
                             {"repeats": r, "blob": b, "fooling": f}))
    out.sort(key=lambda c: (c.meta["repeats"], len(c.meta["blob"])))
    return _finish(out, cfg)


def gen_discord(cfg: dict) -> list:
    ports = str(cfg["target"].get("ports", "19294-19344"))
    space = cfg.get("space", {})
    rnd = random.Random(int(space.get("seed", 1)))
    blobs = space.get("blobs") or [ZERO_BLOB_16, "0x" + "00" * 64, "0x" + rnd.randbytes(32).hex(), "fake_default_quic"]
    scopes = space.get("scopes", ["l7", "all"])
    fools = space.get("fooling", [""])
    out = []
    for sc, r, b, f in itertools.product(scopes, _rep_values(space, 6, 11, 1), blobs, fools):
        pay = "discord_ip_discovery,stun" if sc == "l7" else "all"
        params = [["blob", b], ["repeats", str(r)]] + ([["payload", "all"]] if sc == "all" else []) + _fool_params(f)
        prof = Profile(name=f"scan-discord-{sc}", filter_udp=ports,
                       filter_l7=["discord", "stun"] if sc == "l7" else [], steps=[Step("fake", params, payload=pay)])
        out.append(Candidate(f"discord[{sc}] blob={b[:20]} repeats={r}" + (f" +{f}" if f else ""), prof,
                             {"scope": sc, "repeats": r, "blob": b, "fooling": f}))
    return _finish(out, cfg)


GENERATORS = {"udp": gen_udp, "game": gen_game, "discord": gen_discord}

DEFAULTS = {
    "udp": {"scanner": "udp", "target": {"host": "discord.com", "port": 443, "proto": "udp"}, "l7": "quic",
            "probe": {"mode": "http3", "attempts": 3, "timeout": 3.0},
            "space": {"repeats": {"min": 2, "max": 11, "step": 3}, "blobs": ["fake_default_quic", ZERO_BLOB_16],
                      "fooling": ["", "ip_autottl=-2,3-20:ip6_autottl=-2,3-20"]},
            "limits": {"max_candidates": 40, "stop_on_first_success": False}, "runtime": {"qnum": 210}},
    "game": {"scanner": "game", "target": {"host": "", "ports": "27015-27030"},
             "probe": {"packets": 3, "timeout": 1.0, "sample_ports": 8},
             "space": {"repeats": {"min": 1, "max": 6, "step": 1}, "blobs": [ZERO_BLOB_16, "0x00000000"], "fooling": [""]},
             "limits": {"max_candidates": 30, "stop_on_first_success": False}, "runtime": {"qnum": 210}},
    "discord": {"scanner": "discord", "target": {"host": "", "ports": "19294-19344"},
                "probe": {"duration": 10, "pps": 20},
                "space": {"repeats": {"min": 6, "max": 11, "step": 1}, "scopes": ["l7", "all"], "seed": 1, "fooling": [""]},
                "limits": {"max_candidates": 40, "stop_on_first_success": False}, "runtime": {"qnum": 210}},
}


def merge_defaults(cfg: dict) -> dict:
    base = DEFAULTS[cfg["scanner"]]
    def deep(a, b):
        r = dict(a)
        for k, v in b.items():
            r[k] = deep(a[k], v) if isinstance(v, dict) and isinstance(a.get(k), dict) else v
        return r
    return deep(base, cfg)
