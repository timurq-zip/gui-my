"""Клиент привилегированного помощника: один запрос пароля (pkexec/sudo) на всю сессию."""
from __future__ import annotations
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

from .settings import Settings

HELPER = str(Path(__file__).with_name("helper.py"))


class HelperError(RuntimeError):
    pass


class HelperClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.proc: subprocess.Popen | None = None
        self._q: "queue.Queue[dict]" = queue.Queue()
        self._lock = threading.Lock()
        self._id = 0

    # --- запуск ---
    def command(self) -> list[str]:
        nfq = self.settings.resolve_nfqws2()
        if not nfq:
            raise HelperError("nfqws2 не найден")
        base = [sys.executable, HELPER, "--nfqws2", os.path.abspath(nfq)]
        if os.geteuid() == 0:
            return base
        if self.settings.privilege == "sudo":
            return ["sudo", "-A" if os.environ.get("SUDO_ASKPASS") else "-n", *base]
        return ["pkexec", *base]

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, timeout: float = 120.0) -> None:
        if self.alive:
            return
        self.proc = subprocess.Popen(self.command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, bufsize=1)
        threading.Thread(target=self._reader, daemon=True).start()
        try:
            hello = self._q.get(timeout=timeout)  # ждём ввода пароля пользователем
        except queue.Empty:
            self.close()
            raise HelperError("таймаут ожидания авторизации (pkexec/sudo)")
        if not hello.get("ok"):
            err = hello.get("error") or (self.proc.stderr.read() if self.proc.stderr else "")
            self.close()
            raise HelperError(f"помощник не запустился: {err.strip()}")

    def _reader(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            try:
                self._q.put(json.loads(line))
            except json.JSONDecodeError:
                pass
        self._q.put({"id": -2, "ok": False, "error": "helper exited"})

    # --- вызовы ---
    def call(self, op: str, timeout: float = 30.0, **args) -> dict:
        with self._lock:
            if not self.alive:
                raise HelperError("привилегированный помощник не запущен")
            self._id += 1
            rid = self._id
            assert self.proc and self.proc.stdin
            self.proc.stdin.write(json.dumps({"id": rid, "op": op, "args": args}) + "\n")
            self.proc.stdin.flush()
            while True:
                try:
                    r = self._q.get(timeout=timeout)
                except queue.Empty:
                    raise HelperError(f"таймаут операции {op}")
                if r.get("id") == rid or r.get("id") == -2:
                    break
            if not r.get("ok"):
                raise HelperError(r.get("error", "unknown error"))
            return r

    # удобные обёртки
    def nft_backup(self) -> str: return self.call("nft_backup")["text"]
    def nft_apply(self, ruleset: str) -> None: self.call("nft_apply", ruleset=ruleset)
    def nft_clear(self) -> None: self.call("nft_clear")
    def nft_restore(self, text: str) -> None: self.call("nft_restore", text=text)
    def sysctl_liberal(self) -> None: self.call("sysctl_liberal")
    def start_nfqws2(self, args: list[str], log: str) -> int: return self.call("start", args=args, log=log)["handle"]
    def poll(self, handle: int): return self.call("poll", handle=handle)["returncode"]
    def stop(self, handle: int) -> None: self.call("stop", handle=handle)

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                assert self.proc.stdin
                self.proc.stdin.write(json.dumps({"id": 0, "op": "shutdown"}) + "\n")
                self.proc.stdin.flush()
                self.proc.wait(5)
            except Exception:
                self.proc.kill()
        self.proc = None
