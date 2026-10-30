"""Клиент root-хелпера. Запуск только через pkexec или sudo; UI обязан спросить подтверждение до start()."""
from __future__ import annotations
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
from pathlib import Path


class HelperError(RuntimeError):
    pass


class RootHelper:
    def __init__(self):
        self.p = None
        self.lock = threading.Lock()
        self.q = queue.Queue()
        self._id = 0
        self.noise = []

    @property
    def running(self) -> bool:
        return self.p is not None and self.p.poll() is None

    def start(self, timeout=120):
        if self.running:
            return
        helper = str(Path(__file__).with_name("helper.py"))
        tail = [sys.executable, helper, str(os.getuid()), str(os.getgid()), str(Path.home())]
        if shutil.which("pkexec"):
            cmd = ["pkexec"] + tail
        elif shutil.which("sudo"):
            cmd = ["sudo"] + (["-A"] if os.environ.get("SUDO_ASKPASS") else []) + tail
        else:
            raise HelperError("Не найден ни pkexec, ни sudo")
        self.q = queue.Queue()
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, bufsize=1)
        threading.Thread(target=self._reader, daemon=True).start()
        r = self.call("ping", timeout=timeout)
        if not r.get("ok"):
            raise HelperError("Хелпер не ответил на ping")

    def _reader(self):
        for line in self.p.stdout:
            try:
                self.q.put(json.loads(line))
            except ValueError:
                self.noise.append(line.strip())
        self.q.put({"id": -1, "ok": False, "err": "helper exited: " + " | ".join(self.noise[-3:])})

    def call(self, op: str, timeout=40, **kw) -> dict:
        with self.lock:
            if not self.running:
                raise HelperError("Хелпер не запущен (отказ в авторизации или завершён)")
            self._id += 1
            rid = self._id
            self.p.stdin.write(json.dumps({"id": rid, "op": op, **kw}) + "\n")
            self.p.stdin.flush()
            while True:
                try:
                    r = self.q.get(timeout=timeout)
                except queue.Empty:
                    raise HelperError(f"Таймаут операции {op}")
                if r.get("id") in (rid, -1):
                    return r

    def stop(self):
        if self.running:
            try:
                self.p.stdin.close()
                self.p.wait(8)
            except Exception:
                self.p.kill()
