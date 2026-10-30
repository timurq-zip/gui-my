"""Модель данных. Здесь НЕТ ни одного готового профиля: пользователь создаёт всё сам."""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field, asdict
from pathlib import Path

L7_PROTOCOLS = ["http", "tls", "quic", "stun", "wireguard", "discord", "dht", "xmpp", "mtproto", "dns"]
ZERO_BLOB_16 = "0x00000000000000000000000000000000"


@dataclass
class Step:
    """Один --lua-desync. Пустые фильтры = «наследовать от предыдущего шага» (как в CLI)."""
    func: str = "fake"
    params: list = field(default_factory=list)  # [[ключ, значение_или_пусто], ...]
    payload: str = ""
    in_range: str = ""
    out_range: str = ""

    def desync_arg(self) -> str:
        parts = [self.func] + [k if v == "" else f"{k}={v}" for k, v in self.params]
        return ":".join(parts)


@dataclass
class Profile:
    name: str = "Новый профиль"
    enabled: bool = True
    filter_tcp: str = ""
    filter_udp: str = ""
    filter_l7: list = field(default_factory=list)
    hostlist: str = ""
    hostlist_exclude: str = ""
    steps: list = field(default_factory=list)  # list[Step]

    @classmethod
    def from_dict(cls, d: dict) -> "Profile":
        d = dict(d)
        d["steps"] = [Step(**s) for s in d.get("steps", [])]
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Blob:
    name: str = ""
    value: str = ""  # "0xHEX" или "@/путь/к/файлу"


@dataclass
class LuaInit:
    kind: str = "file"  # file | code
    value: str = ""


@dataclass
class GameFilter:
    enabled: bool = False
    ports: str = ""
    blob: str = ZERO_BLOB_16
    repeats: int = 2


@dataclass
class Settings:
    zapret2_dir: str = "/opt/zapret2"
    nfqws2_path: str = ""
    qnum: int = 200
    debug: bool = True
    packet_limit: int = 12
    intercept_replies: bool = True
    iface: str = ""

    @property
    def lua_dir(self) -> Path:
        return Path(self.zapret2_dir) / "lua"

    def nfqws2_bin(self) -> str:
        if self.nfqws2_path and Path(self.nfqws2_path).exists():
            return self.nfqws2_path
        base = Path(self.zapret2_dir)
        for c in (base / "binaries" / "my" / "nfqws2", base / "nfq2" / "nfqws2"):
            if c.exists():
                return str(c)
        return shutil.which("nfqws2") or ""


@dataclass
class AppState:
    settings: Settings = field(default_factory=Settings)
    profiles: list = field(default_factory=list)
    blobs: list = field(default_factory=list)
    luas: list = field(default_factory=list)
    mode: str = "both"  # tcp | udp | both
    game: GameFilter = field(default_factory=GameFilter)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "AppState":
        def pick(klass, v):
            return klass(**{k: x for k, x in (v or {}).items() if k in klass.__dataclass_fields__})
        return cls(
            settings=pick(Settings, d.get("settings")),
            profiles=[Profile.from_dict(p) for p in d.get("profiles", [])],
            blobs=[pick(Blob, b) for b in d.get("blobs", [])],
            luas=[pick(LuaInit, b) for b in d.get("luas", [])],
            mode=d.get("mode", "both") if d.get("mode") in ("tcp", "udp", "both") else "both",
            game=pick(GameFilter, d.get("game")),
        )
