"""Генерация командной строки nfqws2 из модели. Синтаксис — по docs zapret2."""
from __future__ import annotations
import shlex
from .models import Profile, Step, Settings, AppState, GameFilter
from .paths import LISTS_DIR

DEFAULT_LUA = ("zapret-lib.lua", "zapret-antidpi.lua")


def merge_ports(*vals: str) -> str:
    seen, out = set(), []
    for v in vals:
        for t in (v or "").replace(" ", "").split(","):
            if t and t not in seen:
                seen.add(t)
                out.append(t)
    return ",".join(out)


def game_profile(g: GameFilter):
    """GameFilter: у zapret2 нет встроенного — строим обычный профиль по UDP-портам.
    payload=all нужно, т.к. функции antidpi по умолчанию трогают только известные пейлоады."""
    if not g.enabled or not g.ports.strip():
        return None
    return Profile(name="GameFilter", filter_udp=g.ports.replace(" ", ""),
                   steps=[Step("fake", [["blob", g.blob], ["repeats", str(g.repeats)], ["payload", "all"]],
                               payload="all")])


def active_profiles(st: AppState) -> list:
    res = []
    gp = game_profile(st.game)
    if gp and st.mode in ("udp", "both"):
        res.append(gp)  # первым: профили выбираются по порядку, первый подошедший побеждает
    for p in st.profiles:
        if not p.enabled:
            continue
        t, u = bool(p.filter_tcp.strip()), bool(p.filter_udp.strip())
        if st.mode == "tcp" and u and not t:
            continue
        if st.mode == "udp" and t and not u:
            continue
        res.append(p)
    return res


def profile_tokens(p: Profile, lists_dir=LISTS_DIR) -> list:
    a = []
    if p.filter_tcp.strip():
        a.append(f"--filter-tcp={p.filter_tcp.replace(' ', '')}")
    if p.filter_udp.strip():
        a.append(f"--filter-udp={p.filter_udp.replace(' ', '')}")
    if p.filter_l7:
        a.append("--filter-l7=" + ",".join(p.filter_l7))
    if p.hostlist:
        a.append(f"--hostlist={lists_dir}/{p.hostlist}.txt")
    if p.hostlist_exclude:
        a.append(f"--hostlist-exclude={lists_dir}/{p.hostlist_exclude}.txt")
    for s in p.steps:
        if s.in_range:
            a.append(f"--in-range={s.in_range}")
        if s.out_range:
            a.append(f"--out-range={s.out_range}")
        if s.payload:
            a.append(f"--payload={s.payload}")
        a.append(f"--lua-desync={s.desync_arg()}")
    return a


def build_args(settings: Settings, profiles: list, blobs=(), luas=(), qnum=None, lists_dir=LISTS_DIR) -> list:
    args = [f"--qnum={qnum if qnum is not None else settings.qnum}"]
    if settings.debug:
        args.append("--debug")
    for f in DEFAULT_LUA:
        args.append(f"--lua-init=@{settings.lua_dir / f}")
    for l in luas:
        if l.value.strip():
            args.append(f"--lua-init=@{l.value}" if l.kind == "file" else f"--lua-init={l.value}")
    for b in blobs:
        if b.name.strip() and b.value.strip():
            args.append(f"--blob={b.name}:{b.value}")
    chunks = [profile_tokens(p, lists_dir) for p in profiles]
    for i, c in enumerate(chunks):
        if i:
            args.append("--new")
        args += c
    return args


def build_state_args(st: AppState) -> list:
    return build_args(st.settings, active_profiles(st), st.blobs, st.luas)


def intercept_ports(profiles: list):
    return (merge_ports(*[p.filter_tcp for p in profiles]), merge_ports(*[p.filter_udp for p in profiles]))


def to_shell(args: list, binary: str = "nfqws2") -> str:
    return " \\\n  ".join([shlex.quote(binary)] + [shlex.quote(a) for a in args])
