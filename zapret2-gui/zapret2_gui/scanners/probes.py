"""Пробы доступности. Честно о пределах: см. README, раздел «Что сканеры не умеют»."""
from __future__ import annotations
import os
import random
import re
import shutil
import socket
import subprocess
import time
from collections import Counter


def ping(ip: str, count=3, timeout=2) -> dict:
    exe = "ping6" if ":" in ip and shutil.which("ping6") else "ping"
    if not shutil.which(exe):
        return {"available": False}
    cmd = [exe, "-c", str(count), "-W", str(timeout), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=count * (timeout + 1) + 2)
    except subprocess.TimeoutExpired:
        return {"available": True, "ok": False, "loss": 100}
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", r.stdout)
    loss = float(m.group(1)) if m else 100.0
    rtt = re.search(r"= [\d.]+/([\d.]+)/", r.stdout)
    return {"available": True, "ok": loss < 100, "loss": loss, "rtt_ms": float(rtt.group(1)) if rtt else None}


# ---------- пакеты ----------
def quic_vn_probe_packet() -> bytes:
    dcid, scid = os.urandom(8), os.urandom(8)
    hdr = bytes([0xC0 | random.randint(0, 0x0F)]) + bytes.fromhex("1a2a3a4a") + b"\x08" + dcid + b"\x08" + scid
    return hdr + os.urandom(1200 - len(hdr))


def quic_vn_ok(data: bytes, sent: bytes) -> bool:
    return len(data) >= 7 and bool(data[0] & 0x80) and data[1:5] == b"\x00\x00\x00\x00"


def stun_request():
    tid = os.urandom(12)
    return b"\x00\x01\x00\x00\x21\x12\xa4\x42" + tid


def stun_ok(data: bytes, sent: bytes) -> bool:
    return len(data) >= 20 and data[:2] == b"\x01\x01" and data[4:8] == b"\x21\x12\xa4\x42" and data[8:20] == sent[8:20]


def wg_like_packet() -> bytes:
    return b"\x01\x00\x00\x00" + os.urandom(144)


# ---------- UDP ----------
def udp_probe(ip, port, make_payload, check=None, attempts=3, timeout=2.0) -> dict:
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    ev, rtts = Counter(), []
    for _ in range(attempts):
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            sent = make_payload()
            t = time.monotonic()
            s.send(sent)
            data = s.recv(65535)
            if check is None or check(data, sent):
                ev["valid_response"] += 1
                rtts.append((time.monotonic() - t) * 1000)
            else:
                ev["invalid_response"] += 1
        except socket.timeout:
            ev["timeout"] += 1
        except ConnectionRefusedError:
            ev["icmp_unreachable"] += 1
        except OSError as e:
            ev[f"oserror_{e.errno}"] += 1
        finally:
            s.close()
    return {"evidence": dict(ev), "rtt_ms": round(sum(rtts) / len(rtts), 1) if rtts else None, "attempts": attempts}


def http3_supported() -> bool:
    if not shutil.which("curl"):
        return False
    try:
        return "HTTP3" in subprocess.run(["curl", "--version"], capture_output=True, text=True).stdout
    except OSError:
        return False


def http3_probe(domain, ip, port, timeout=5.0, attempts=2) -> dict:
    """Настоящий QUIC Initial с SNI строит curl; это единственная проба, реально проверяющая SNI-блокировку QUIC."""
    ev, rtts = Counter(), []
    for _ in range(attempts):
        cmd = ["curl", "--http3-only", "-sS", "-o", os.devnull, "-m", str(timeout), "-w", "%{http_code} %{time_connect}",
               "--resolve", f"{domain}:{port}:{ip}", f"https://{domain}:{port}/"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        except subprocess.TimeoutExpired:
            ev["timeout"] += 1
            continue
        code, _, tc = r.stdout.strip().partition(" ")
        if r.returncode == 0 and code not in ("000", ""):
            ev["valid_response"] += 1
            try:
                rtts.append(float(tc) * 1000)
            except ValueError:
                pass
        else:
            ev[f"curl_exit_{r.returncode}"] += 1
    return {"evidence": dict(ev), "rtt_ms": round(sum(rtts) / len(rtts), 1) if rtts else None, "attempts": attempts}


# ---------- интерпретация ----------
def judge_strict(res: dict) -> str:
    """Спека UDP-сканера: валидный ответ — успех; таймаут/ICMP unreachable — провал."""
    return "ok" if res["evidence"].get("valid_response") else "fail"


def probe_game(ip, ports, packets=3, timeout=1.0, sample=8, seed=1) -> dict:
    rnd = random.Random(seed)
    pl = sorted(set(ports))
    if len(pl) > sample:
        pl = sorted(rnd.sample(pl, sample))
    ev = Counter()
    for p in pl:
        r = udp_probe(ip, p, lambda: bytes(rnd.getrandbits(8) for _ in range(rnd.randint(32, 256))),
                      None, packets, timeout)
        ev.update(r["evidence"])
    return {"evidence": dict(ev), "ports_tested": pl}


def judge_game(ev: dict, ping_before: dict, ping_after: dict) -> tuple:
    if ping_before.get("ok") and ping_after.get("available") and not ping_after.get("ok"):
        return "fail", "после запуска стратегии пинг до хоста пропал"
    if ev.get("valid_response") or ev.get("invalid_response"):
        return "ok", "получен ответ по UDP"
    if ev.get("icmp_unreachable"):
        return "reachable", "ICMP port unreachable: пакет дошёл до хоста (порт закрыт), DPI его не съел"
    if any(k.startswith("oserror") for k in ev):
        return "fail", "ошибки отправки сокета"
    return "inconclusive", "ответов нет: эхо-сервера нет — оценка только по логам и пингу"


def probe_stream(ip, ports, duration=10.0, pps=20) -> dict:
    """Шлёт UDP по всем портам диапазона через connected-сокеты (чтобы ядро сообщало об ICMP-ошибках)."""
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    socks = {}
    ev, sent, i = Counter(), 0, 0
    pl = sorted(ports)
    for p in pl:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.setblocking(False)
        try:
            s.connect((ip, p))
            socks[p] = s
        except OSError as e:
            ev[f"oserror_{e.errno}"] += 1
    end = time.monotonic() + duration
    while socks and time.monotonic() < end:
        port = pl[i % len(pl)]
        i += 1
        s = socks.get(port)
        if s is None:
            continue
        try:
            s.send(os.urandom(random.randint(100, 1200)))
            sent += 1
        except ConnectionRefusedError:
            ev["icmp_unreachable"] += 1
        except BlockingIOError:
            ev["eagain"] += 1
        except OSError as e:
            ev[f"oserror_{e.errno}"] += 1
        try:
            s.recv(65535)
            ev["valid_response"] += 1
        except (BlockingIOError, ConnectionRefusedError, OSError):
            pass
        time.sleep(1.0 / pps)
    for s in socks.values():
        s.close()
    return {"evidence": dict(ev), "sent": sent}
