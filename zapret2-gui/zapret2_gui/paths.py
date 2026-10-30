"""Каталоги приложения (XDG)."""
import os
from pathlib import Path

APP = "zapret2-gui"
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / APP
LISTS_DIR = CONFIG_DIR / "lists"
STATE_FILE = CONFIG_DIR / "state.yaml"
SCANS_DIR = STATE_DIR / "scans"
BACKUP_DIR = STATE_DIR / "nft-backups"


def ensure_dirs() -> None:
    for d in (CONFIG_DIR, LISTS_DIR, SCANS_DIR, BACKUP_DIR):
        d.mkdir(parents=True, exist_ok=True)
