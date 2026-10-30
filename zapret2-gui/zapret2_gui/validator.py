"""Эвристический валидатор параметров nfqws2.
Ошибка (error) = nfqws2 почти наверняка откажется стартовать. Предупреждение (warn) = подозрительно,
но возможно корректно (например, пользовательский Lua). Дополнительно — `nfqws2 --dry-run`, если поддерживается."""
from __future__ import annotations
import os
import re
import subprocess
from dataclasses import dataclass
from .functions_db import FUNCS, COMMON, PAYLOAD_TYPES, BUILTIN_BLOBS
from .models import L7_PROTOCOLS


@dataclass
class Issue:
    level: str  # error | warn | info
    msg: str

    def __str__(self):
        return f"[{self.level.upper()}] {self.msg}"


VALUE_OPTS = {"qnum", "lua-init", "blob", "filter-tcp", "filter-udp", "filter-l7", "payload", "in-range",
              "out-range", "hostlist", "hostlist-exclude", "ipset", "ipset-exclude", "lua-desync", "user",
              "pidfile", "name", "comment", "hostlist-auto", "hostlist-auto-debug"}
FLAG_OPTS = {"new", "debug", "daemon", "server", "dry-run", "version", "help"}
PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
RANGE_RE = re.compile(r"^(?:[ax]|(?:[ndbs]\d+)?[-<](?:[ndbs]\d+)?)$")
HEX_RE = re.compile(r"^0x([0-9a-fA-F]{2})+$")
POS_STRICT = re.compile(r"^(?:-?\d+|(?:method|host|endhost|sld|endsld|midsld|sniext|extlen|midhost)(?:[+-]\d+)?)$")
POS_LOOSE = re.compile(r"^[A-Za-z0-9_+\-]+$")
AUTOTTL_RE = re.compile(r"^-?\d+,\d+-\d+$")
INT_RANGES = {"repeats": (1, 1000), "ip_ttl": (0, 255), "ip6_ttl": (0, 255), "wsize": (0, 65535), "scale": (0, 14)}
SIGNED = {"tcp_seq", "tcp_ack", "tcp_ts"}
BLOB_PARAMS = {"blob", "pattern", "seqovl_pattern"}
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
FATAL_LOG = re.compile(r"(?i)lua[^\n]{0,40}error|stack traceback|unknown (option|function|parameter)|"
                       r"invalid (parameter|value|option)|failed to (load|init|open)|cannot (open|load)|bad (param|arg)")


def _ports(v, what, out):
    if not PORTS_RE.match(v):
        out.append(Issue("error", f"{what}: «{v}» — ожидается список портов/диапазонов вида 80,443,19294-19344"))
        return
    for t in v.split(","):
        lo, _, hi = t.partition("-")
        lo, hi = int(lo), int(hi or lo)
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535) or lo > hi:
            out.append(Issue("error", f"{what}: некорректный порт/диапазон «{t}»"))


def _pos(v, out, fn):
    for t in v.split(","):
        if POS_STRICT.match(t):
            continue
        if POS_LOOSE.match(t):
            out.append(Issue("warn", f"{fn}: маркер «{t}» не из известного списка (method, host, endhost, sld, endsld, midsld, sniext, extlen, числа ±N)"))
        else:
            out.append(Issue("error", f"{fn}: недопустимый маркер pos «{t}»"))


def validate_desync(arg: str, blobs: set, lua_funcs: set, relaxed_blobs=False) -> list:
    out = []
    parts = arg.split(":")
    fn = parts[0]
    if not NAME_RE.match(fn):
        return [Issue("error", f"--lua-desync: некорректное имя функции «{fn}»")]
    spec = FUNCS.get(fn)
    if spec is None and fn not in lua_funcs:
        out.append(Issue("warn", f"Функция «{fn}» не найдена в справочнике и не определена в ваших --lua-init. "
                                 "Если она есть в zapret-antidpi.lua — игнорируйте."))
    known = {p.name for p in (spec.params if spec else [])} | {p.name for p in COMMON}
    for tok in parts[1:]:
        if tok == "":
            out.append(Issue("error", f"{fn}: пустой параметр (двойное двоеточие?)"))
            continue
        k, eq, v = tok.partition("=")
        if spec and k not in known:
            out.append(Issue("warn", f"{fn}: параметр «{k}» не найден в справочнике (опечатка?)"))
        if k in INT_RANGES:
            lo, hi = INT_RANGES[k]
            if not re.fullmatch(r"-?\d+", v) or not lo <= int(v) <= hi:
                out.append(Issue("error", f"{fn}:{k}={v!r} — нужно целое {lo}..{hi}"))
        elif k in SIGNED and not re.fullmatch(r"-?\d+", v):
            out.append(Issue("error", f"{fn}:{k}={v!r} — нужно целое число"))
        elif k in ("ip_autottl", "ip6_autottl") and not AUTOTTL_RE.match(v):
            out.append(Issue("error", f"{fn}:{k}={v!r} — формат delta,min-max, например -2,3-20"))
        elif k == "pos":
            if not v:
                out.append(Issue("error", f"{fn}: pos без значения"))
            else:
                _pos(v, out, fn)
        elif k == "seqovl" and not (re.fullmatch(r"\d+", v) or v.startswith("#")):
            out.append(Issue("error", f"{fn}:seqovl={v!r} — число или #имя_блоба"))
        elif k in BLOB_PARAMS:
            if not v:
                out.append(Issue("error", f"{fn}:{k} без значения"))
            elif v.startswith("0x") and not HEX_RE.match(v):
                out.append(Issue("error", f"{fn}:{k}={v} — HEX должен иметь чётное число цифр (0x00 0x0A…)"))
            elif not v.startswith(("0x", "%")) and v not in blobs:
                lvl = "warn" if (relaxed_blobs or v.startswith("fake_default_")) else "error"
                out.append(Issue(lvl, f"{fn}:{k}={v} — блоб не объявлен (--blob) и не встроенный"))
        elif k == "payload" and v:
            for t in v.split(","):
                if t not in PAYLOAD_TYPES:
                    out.append(Issue("warn", f"{fn}: тип payload «{t}» не в списке известных"))
    if fn == "fake" and not any(t.startswith("blob") for t in parts[1:]):
        out.append(Issue("info", "fake без blob= использует блоб по умолчанию"))
    return out


def _lua_defs(args: list):
    funcs, issues = set(), []
    for a in args:
        if not a.startswith("--lua-init="):
            continue
        v = a.split("=", 1)[1]
        code = v
        if v.startswith("@"):
            path = v[1:]
            if not os.path.isfile(path):
                issues.append(Issue("error", f"--lua-init: файл не найден: {path}"))
                continue
            try:
                code = open(path, encoding="utf-8", errors="replace").read()
            except OSError as e:
                issues.append(Issue("error", f"--lua-init: не читается {path}: {e}"))
                continue
        funcs.update(re.findall(r"function\s+([A-Za-z_]\w*)", code))
    return funcs, issues


def validate_args(args: list, extra_blobs=()) -> list:
    out = []
    lua_funcs, li = _lua_defs(args)
    out += li
    blobs = set(BUILTIN_BLOBS) | set(extra_blobs)
    for a in args:
        if a.startswith("--blob="):
            name, _, val = a.split("=", 1)[1].partition(":")
            if not NAME_RE.match(name):
                out.append(Issue("error", f"--blob: некорректное имя «{name}»"))
            elif HEX_RE.match(val):
                pass
            elif re.match(r"^(\+\d+)?@", val):
                path = val.split("@", 1)[1]
                if not os.path.isfile(path):
                    out.append(Issue("error", f"--blob={name}: файл не найден: {path}"))
            else:
                out.append(Issue("error", f"--blob={name}: значение должно быть 0xHEX (чётное число цифр) или [+смещение]@файл"))
            blobs.add(name)
    relaxed = any(a.startswith("--lua-desync=luaexec") for a in args)
    profiles, cur = [], []
    for a in args:
        if a == "--new":
            profiles.append(cur)
            cur = []
        else:
            cur.append(a)
    profiles.append(cur)
    sigs = {}
    for n, prof in enumerate(profiles, 1):
        tag = f"Профиль {n}"
        desyncs, tcp, udp, l7s, hl = 0, "", "", [], False
        for a in prof:
            if not a.startswith("--"):
                out.append(Issue("error", f"{tag}: «{a}» — не опция (ожидается --имя[=значение])"))
                continue
            name, eq, val = a[2:].partition("=")
            if name not in VALUE_OPTS and name not in FLAG_OPTS:
                out.append(Issue("warn", f"{tag}: опция --{name} не в списке известных этому GUI"))
                continue
            if name in VALUE_OPTS and name not in ("hostlist-auto-debug",) and not eq:
                out.append(Issue("error", f"{tag}: --{name} требует значение"))
                continue
            if name == "qnum" and not (val.isdigit() and 0 <= int(val) <= 65535):
                out.append(Issue("error", f"--qnum={val}: номер очереди 0..65535"))
            elif name in ("filter-tcp", "filter-udp"):
                _ports(val, f"{tag} --{name}", out)
                tcp, udp = (val, udp) if name == "filter-tcp" else (tcp, val)
            elif name == "filter-l7":
                l7s = val.split(",")
                for t in l7s:
                    if t not in L7_PROTOCOLS and t != "unknown":
                        out.append(Issue("warn", f"{tag}: протокол l7 «{t}» неизвестен GUI"))
            elif name == "payload":
                for t in val.split(","):
                    if t not in PAYLOAD_TYPES:
                        out.append(Issue("warn", f"{tag}: тип payload «{t}» не в списке известных"))
            elif name in ("in-range", "out-range"):
                if not RANGE_RE.match(val) or val in ("-", "<"):
                    out.append(Issue("error", f"{tag} --{name}={val}: формат mX-mY, mX<mY, -mY, mX-, a, x (m = n|d|b|s)"))
            elif name in ("hostlist", "hostlist-exclude"):
                hl = True
                if not os.path.isfile(val):
                    out.append(Issue("error", f"{tag}: файл хостлиста не найден: {val}"))
                elif os.path.getsize(val) == 0:
                    out.append(Issue("warn", f"{tag}: хостлист пуст: {val}"))
            elif name == "lua-desync":
                desyncs += 1
                out += [Issue(i.level, f"{tag}: {i.msg}") for i in validate_desync(val, blobs, lua_funcs, relaxed)]
        if not desyncs:
            out.append(Issue("warn", f"{tag}: нет ни одного --lua-desync — профиль ничего не меняет"))
        if "quic" in l7s and tcp and not udp:
            out.append(Issue("warn", f"{tag}: l7=quic работает по UDP, а задан только --filter-tcp"))
        if "http" in l7s and udp and not tcp:
            out.append(Issue("warn", f"{tag}: l7=http работает по TCP, а задан только --filter-udp"))
        sig = (tcp, udp, tuple(l7s), hl)
        if sig in sigs and not hl:
            out.append(Issue("warn", f"{tag}: те же фильтры, что у профиля {sigs[sig]} — он никогда не сработает (побеждает первый подходящий)"))
        sigs.setdefault(sig, n)
    return out


def has_errors(issues) -> bool:
    return any(i.level == "error" for i in issues)


def scan_log_for_fatal(text: str) -> list:
    return [l.strip() for l in text.splitlines() if FATAL_LOG.search(l)][:5]


def dry_run(binary: str, args: list, timeout=10):
    """Возвращает (статус, вывод). статус: ok | fail | unsupported | missing."""
    if not binary or not os.path.exists(binary):
        return "missing", "бинарник nfqws2 не найден (Настройки → путь к zapret2)"
    try:
        r = subprocess.run([binary, "--dry-run"] + args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "unsupported", "dry-run завис: возможно, флаг не поддерживается этой сборкой"
    txt = (r.stdout + r.stderr).strip()
    if r.returncode == 0:
        return "ok", txt
    if re.search(r"(?i)(unrecognized|unknown|invalid) option[^\n]*dry-run|dry-run[^\n]*(unrecognized|unknown)", txt):
        return "unsupported", "эта сборка nfqws2 не знает --dry-run"
    return "fail", txt
