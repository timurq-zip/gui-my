"""Движок сканирования: временные профили → nfqws2 → проба → results.json."""
from __future__ import annotations
import json
import shutil
import time
from datetime import datetime
from pathlib import Path

import yaml

from ..cli_builder import build_args, profile_tokens
from ..dnsutil import resolve
from ..models import AppState
from ..nft import build_ruleset, TABLE
from ..paths import SCANS_DIR, BACKUP_DIR, ensure_dirs
from ..privilege import RootHelper
from ..validator import validate_args, has_errors, scan_log_for_fatal
from . import probes
from .strategies import GENERATORS, merge_defaults, parse_ports

RANK = {"ok": 3, "stable": 2, "reachable": 2, "baseline": 1, "inconclusive": 1, "fail": 0, "invalid": -1}


class ScanRunner:
    def __init__(self, cfg: dict, state: AppState, helper: RootHelper, on_progress=None, should_stop=lambda: False):
        self.cfg = merge_defaults(cfg)
        self.state, self.helper = state, helper
        self.progress = on_progress or (lambda *a: None)
        self.should_stop = should_stop
        self.results, self.pid = [], None

    # ---- помощники ----
    def _write_json(self, extra=None):
        best = max(self.results, key=lambda r: (RANK.get(r["status"], -1), -r.get("meta", {}).get("repeats", 0)), default=None)
        data = {"session": self.dir.name, "scanner": self.cfg["scanner"], "target": self.cfg["target"],
                "resolved": self.resolved, "baseline_ping": self.base_ping,
                "best": best["name"] if best and RANK.get(best["status"], -1) > 0 else None,
                "results": self.results}
        data.update(extra or {})
        (self.dir / "results.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")

    def _stop_proc(self):
        if self.pid:
            try:
                self.helper.call("stop", pid=self.pid)
            except Exception:
                pass
            self.pid = None

    def _log_marker(self, text):
        with open(self.logp, "a", encoding="utf-8") as f:
            f.write(f"\n===== {datetime.now().isoformat(timespec='seconds')} {text} =====\n")

    # ---- запуск ----
    def run(self) -> Path:
        ensure_dirs()
        cfg, st = self.cfg, self.state
        sc = cfg["scanner"]
        self.dir = SCANS_DIR / (datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + sc)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.logp = self.dir / "nfqws2_debug.log"
        self.logp.touch()
        qnum = int(cfg["runtime"]["qnum"])
        host = cfg["target"].get("host", "").strip()
        self.resolved = resolve(host) if host else {"v4": [], "v6": [], "via": "none"}
        ips = self.resolved["v4"] + self.resolved["v6"]
        if sc == "udp" and not ips:
            raise RuntimeError(f"Не удалось разрезолвить {host}")
        if sc in ("game", "discord") and not ips:
            raise RuntimeError("Укажите IP/домен сервера (цель), к которой будут слаться пробные пакеты")
        target_ip = (self.resolved["v4"] or self.resolved["v6"])[0]
        cands = GENERATORS[sc](cfg)
        if not cands:
            raise RuntimeError("Пространство поиска пусто — проверьте repeats/blobs")
        ports_union = ",".join(sorted({c.profile.filter_udp for c in cands}))
        (self.dir / "config.yaml").write_text(yaml.safe_dump({
            "session": self.dir.name, "created": datetime.now().isoformat(timespec="seconds"),
            "scan_config": cfg, "resolved": self.resolved, "nfqws2_template": "см. cli в candidates",
            "candidates": [{"name": c.name, "cli": " ".join(profile_tokens(c.profile)), "meta": c.meta} for c in cands],
        }, allow_unicode=True, sort_keys=False), "utf-8")

        self.base_ping = probes.ping(target_ip)
        # бэкап nftables: и в папку сессии, и в общий каталог
        bk = BACKUP_DIR / f"nft-{datetime.now().strftime('%Y%m%d-%H%M%S')}.nft"
        for p in (self.dir / "nft-backup.nft", bk):
            r = self.helper.call("nft_backup", path=str(p))
            if not r.get("ok"):
                raise RuntimeError(f"Бэкап nftables не удался: {r.get('err')}")
        old_sysctl = self.helper.call("sysctl_liberal", value=1).get("old")
        script = build_ruleset("", ports_union, qnum, st.settings.packet_limit, st.settings.intercept_replies,
                               st.settings.iface, addrs=ips)
        r = self.helper.call("nft_apply", script=script)
        if not r.get("ok"):
            raise RuntimeError(f"nft: {r.get('err')}")
        try:
            for i, c in enumerate(cands, 1):
                if self.should_stop():
                    break
                self.progress(f"[{i}/{len(cands)}] {c.name}", i - 1, len(cands))
                res = self._eval(c, qnum, target_ip, host)
                self.results.append(res)
                self._write_json()
                self.progress(f"{res['status']}: {c.name}", i, len(cands), res)
                if cfg["limits"].get("stop_on_first_success") and res["status"] == "ok":
                    break
        finally:
            self._stop_proc()
            self.helper.call("nft_delete", table=TABLE)
            if old_sysctl is not None:
                self.helper.call("sysctl_liberal", value=old_sysctl)
            self._write_json({"finished": datetime.now().isoformat(timespec="seconds")})
        return self.dir

    def _eval(self, c, qnum, ip, host) -> dict:
        st, cfg = self.state, self.cfg
        res = {"name": c.name, "cli": " ".join(profile_tokens(c.profile)), "meta": c.meta}
        args = build_args(st.settings, [c.profile], st.blobs, st.luas, qnum=qnum)
        issues = validate_args(args, extra_blobs=[b.name for b in st.blobs])
        if has_errors(issues):
            return {**res, "status": "invalid", "evidence": {}, "notes": [str(i) for i in issues if i.level == "error"]}
        binary = st.settings.nfqws2_bin()
        if not binary:
            raise RuntimeError("nfqws2 не найден: укажите путь в «Режимы обхода → Настройки»")
        off = self.logp.stat().st_size
        self._log_marker(f"CANDIDATE {c.name}\n# {res['cli']}")
        off = self.logp.stat().st_size
        r = self.helper.call("start", argv=[binary] + args, log=str(self.logp))
        if not r.get("ok"):
            return {**res, "status": "fail", "evidence": {}, "notes": [f"не удалось запустить: {r.get('err')}"]}
        self.pid = r["pid"]
        time.sleep(0.9)
        notes = []
        if not self.helper.call("alive", pid=self.pid).get("alive"):
            self.pid = None
            tail = self.logp.read_text("utf-8", "replace")[off:][-400:]
            return {**res, "status": "fail", "evidence": {"nfqws2_exited": 1}, "notes": ["nfqws2 завершился сразу после старта", tail]}
        t0 = time.monotonic()
        sc = cfg["scanner"]
        pr = cfg["probe"]
        if sc == "udp":
            status, ev, rtt, notes = self._probe_udp(ip, host, pr)
        elif sc == "game":
            ports = parse_ports(cfg["target"]["ports"])
            g = probes.probe_game(ip, ports, int(pr["packets"]), float(pr["timeout"]), int(pr["sample_ports"]))
            pa = probes.ping(ip)
            status, why = probes.judge_game(g["evidence"], self.base_ping, pa)
            ev, rtt, notes = g["evidence"], None, [why, "ports: " + ",".join(map(str, g["ports_tested"]))]
        else:
            ports = parse_ports(cfg["target"]["ports"])
            g = probes.probe_stream(ip, ports, float(pr["duration"]), int(pr["pps"]))
            alive = self.helper.call("alive", pid=self.pid).get("alive")
            pa = probes.ping(ip)
            ev, rtt = g["evidence"], None
            bad_os = any(k.startswith("oserror") for k in ev)
            if not alive:
                status, notes = "fail", ["nfqws2 упал во время теста"]
            elif bad_os:
                status, notes = "fail", ["ошибки отправки сокета"]
            elif self.base_ping.get("ok") and pa.get("available") and not pa.get("ok"):
                status, notes = "fail", ["пинг до хоста пропал во время теста"]
            elif ev.get("valid_response"):
                status, notes = "ok", ["получены ответы"]
            else:
                status, notes = "stable", [f"отправлено {g['sent']} пакетов, nfqws2 жив. ТРЕБУЕТ ручной проверки в реальном стриме Discord"]
        self._stop_proc()
        fatal = scan_log_for_fatal(self.logp.read_text("utf-8", "replace")[off:])
        if fatal:
            status, notes = "fail", notes + ["в логе nfqws2: " + " | ".join(fatal)]
        return {**res, "status": status, "evidence": ev, "rtt_ms": rtt, "duration_s": round(time.monotonic() - t0, 2), "notes": notes}

    def _probe_udp(self, ip, host, pr):
        l7, port = self.cfg["l7"], int(self.cfg["target"]["port"])
        att, to = int(pr["attempts"]), float(pr["timeout"])
        if l7 == "quic":
            if pr.get("mode") == "http3" and probes.http3_supported() and host and not host.replace(".", "").isdigit():
                r = probes.http3_probe(host, ip, port, to, att)
                return probes.judge_strict(r), r["evidence"], r["rtt_ms"], ["curl --http3-only (настоящий QUIC Initial с SNI)"]
            r = probes.udp_probe(ip, port, probes.quic_vn_probe_packet, probes.quic_vn_ok, att, to)
            st = "baseline" if probes.judge_strict(r) == "ok" else "fail"
            return st, r["evidence"], r["rtt_ms"], ["Version Negotiation: проверяет только доставку UDP, НЕ SNI-блокировку (нужен curl с HTTP/3)"]
        if l7 == "stun":
            r = probes.udp_probe(ip, port, probes.stun_request, probes.stun_ok, att, to)
            return probes.judge_strict(r), r["evidence"], r["rtt_ms"], ["STUN Binding Request/Response"]
        r = probes.udp_probe(ip, port, probes.wg_like_packet, None, att, to)
        if r["evidence"].get("icmp_unreachable"):
            return "fail", r["evidence"], None, ["ICMP port unreachable"]
        if r["evidence"].get("valid_response"):
            return "ok", r["evidence"], r["rtt_ms"], []
        return "inconclusive", r["evidence"], None, ["WireGuard молча игнорирует чужие пакеты: ответа быть не может"]
