"""Модель данных: профили, блобы, режимы, GameFilter. Пресетов здесь нет — всё создаёт пользователь."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any

TCP_L7 = {"http", "tls", "xmpp", "mtproto"}
UDP_L7 = {"quic", "stun", "wireguard", "discord", "dht"}
GAME_ZERO_BLOB = "0x" + "00" * 16  # из ТЗ: нулевой блоб 16 байт


@dataclass
class Blob:
    name: str
    value: str  # "0xHEX" или "@/путь/к/файлу" (допустимо "+ofs@файл")


@dataclass
class Instance:
    """Один --lua-desync. params — фрагменты CLI: 'blob=fake_default_tls', 'tcp_md5', 'repeats=6'."""
    func: str
    params: list[str] = field(default_factory=list)
    payload: str = ""    # --payload перед этим инстансом (наследуется следующими)
    out_range: str = ""  # --out-range
    in_range: str = ""   # --in-range

    def param_dict(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for p in self.params:
            k, _, v = p.partition("=")
            out[k] = v
        return out

    def to_arg(self) -> str:
        return "--lua-desync=" + ":".join([self.func, *self.params])


@dataclass
class Profile:
    name: str = "Новый профиль"
    enabled: bool = True
    filter_tcp: str = ""
    filter_udp: str = ""
    filter_l7: list[str] = field(default_factory=list)
    hostlists: list[str] = field(default_factory=list)          # имена списков (LISTS_DIR/<имя>.txt)
    hostlists_exclude: list[str] = field(default_factory=list)
    instances: list[Instance] = field(default_factory=list)
    extra: str = ""  # «сырые» дополнительные аргументы для профи (shlex)

    def transport(self) -> str:
        if self.filter_tcp and not self.filter_udp:
            return "tcp"
        if self.filter_udp and not self.filter_tcp:
            return "udp"
        if not self.filter_tcp and not self.filter_udp and self.filter_l7:
            l7 = set(self.filter_l7)
            if l7 <= TCP_L7:
                return "tcp"
            if l7 <= UDP_L7:
                return "udp"
        return "both"


@dataclass
class GameFilter:
    enabled: bool = False
    ports: str = ""                 # "27015-27030,3074"
    blob: str = GAME_ZERO_BLOB
    repeats: int = 2
    first_packets: int = 10         # --out-range=-nN (только первые N пакетов потока)


@dataclass
class Modes:
    transport: str = "both"  # off | tcp | udp | both


@dataclass
class Config:
    profiles: list[Profile] = field(default_factory=list)
    blobs: list[Blob] = field(default_factory=list)
    lua_inits: list[str] = field(default_factory=list)  # "@/path.lua" или строка Lua-кода
    modes: Modes = field(default_factory=Modes)
    gamefilter: GameFilter = field(default_factory=GameFilter)

    # --- YAML ---
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Config":
        d = d or {}
        profiles = []
        for p in d.get("profiles", []):
            insts = [Instance(**i) for i in p.get("instances", [])]
            pp = {k: v for k, v in p.items() if k != "instances"}
            profiles.append(Profile(**pp, instances=insts))
        return cls(
            profiles=profiles,
            blobs=[Blob(**b) for b in d.get("blobs", [])],
            lua_inits=list(d.get("lua_inits", [])),
            modes=Modes(**d.get("modes", {})),
            gamefilter=GameFilter(**d.get("gamefilter", {})),
        )
