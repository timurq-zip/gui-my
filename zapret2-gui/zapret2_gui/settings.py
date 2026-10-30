"""Настройки приложения (не профили): где nfqws2, Lua, номер очереди и т.д."""
from __future__ import annotations
import shutil
from dataclasses import dataclass, asdict, fields
from pathlib import Path

import yaml

from . import paths

NFQWS2_CANDIDATES = [
    "/opt/zapret2/nfq2/nfqws2",
    "/opt/zapret2/binaries/linux-x86_64/nfqws2",
    "/usr/local/bin/nfqws2",
    "/usr/bin/nfqws2",
    str(Path.home() / "zapret2/nfq2/nfqws2"),
    str(Path.home() / "zapret2/binaries/linux-x86_64/nfqws2"),
]
ZAPRET_DIR_CANDIDATES = ["/opt/zapret2", "/usr/share/zapret2", str(Path.home() / "zapret2")]


@dataclass
class Settings:
    nfqws2_path: str = ""      # пусто = автоопределение
    zapret2_dir: str = ""      # каталог с подкаталогом lua/
    qnum: int = 200
    desync_mark: str = "0x40000000"
    ct_packets: int = 12       # перехватывать только первые N пакетов соединения
    privilege: str = "pkexec"  # pkexec | sudo
    debug_log: bool = True

    # --- автоопределение -------------------------------------------------
    def resolve_nfqws2(self) -> str:
        if self.nfqws2_path and Path(self.nfqws2_path).is_file():
            return self.nfqws2_path
        w = shutil.which("nfqws2")
        if w:
            return w
        for c in NFQWS2_CANDIDATES:
            if Path(c).is_file():
                return c
        return ""

    def resolve_lua_dir(self) -> str:
        bases = [self.zapret2_dir] if self.zapret2_dir else []
        bases += ZAPRET_DIR_CANDIDATES
        n = self.resolve_nfqws2()
        if n:  # <root>/nfq2/nfqws2 или <root>/binaries/<arch>/nfqws2
            p = Path(n).resolve()
            bases += [str(p.parent.parent), str(p.parent.parent.parent)]
        for b in bases:
            if b and (Path(b) / "lua" / "zapret-lib.lua").is_file():
                return str(Path(b) / "lua")
        return ""

    # --- (де)сериализация ------------------------------------------------
    def save(self) -> None:
        paths.ensure_dirs()
        paths.SETTINGS_FILE.write_text(yaml.safe_dump(asdict(self), allow_unicode=True), encoding="utf-8")

    @classmethod
    def load(cls) -> "Settings":
        s = cls()
        try:
            data = yaml.safe_load(paths.SETTINGS_FILE.read_text(encoding="utf-8")) or {}
            names = {f.name for f in fields(cls)}
            for k, v in data.items():
                if k in names:
                    setattr(s, k, v)
        except FileNotFoundError:
            pass
        return s
