import re
import yaml
from .models import AppState
from .paths import STATE_FILE, LISTS_DIR, ensure_dirs

_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def load_state() -> AppState:
    ensure_dirs()
    if STATE_FILE.exists():
        try:
            return AppState.from_dict(yaml.safe_load(STATE_FILE.read_text("utf-8")) or {})
        except Exception:
            STATE_FILE.rename(STATE_FILE.with_suffix(".broken"))
    return AppState()


def save_state(st: AppState) -> None:
    ensure_dirs()
    STATE_FILE.write_text(yaml.safe_dump(st.to_dict(), allow_unicode=True, sort_keys=False), "utf-8")


# ---- хостлисты ----
def valid_list_name(n: str) -> bool:
    return bool(_NAME.match(n))


def list_names() -> list:
    ensure_dirs()
    return sorted(p.stem for p in LISTS_DIR.glob("*.txt"))


def list_path(name: str):
    return LISTS_DIR / f"{name}.txt"


def read_list(name: str) -> str:
    p = list_path(name)
    return p.read_text("utf-8") if p.exists() else ""


def normalize_domains(text: str) -> str:
    out, seen = [], set()
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if not s.startswith("#"):
            s = re.sub(r"^[a-z]+://", "", s.lower()).split("/")[0].strip(".")
            if not s or s in seen:
                continue
            seen.add(s)
        out.append(s)
    return "\n".join(out) + ("\n" if out else "")


def write_list(name: str, text: str) -> None:
    if not valid_list_name(name):
        raise ValueError("Имя списка: латиница, цифры, _ . - (до 64 символов)")
    ensure_dirs()
    list_path(name).write_text(normalize_domains(text), "utf-8")


def delete_list(name: str) -> None:
    list_path(name).unlink(missing_ok=True)
