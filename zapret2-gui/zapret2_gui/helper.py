#!/usr/bin/env python3
"""Root-хелпер. Запускается ОДИН раз через pkexec/sudo и общается с GUI строками JSON по stdin/stdout.
Умеет только: nft (backup/apply/delete/restore), sysctl conntrack-liberal, запуск/остановка nfqws2."""
import json
import os
import subprocess
import sys

procs = {}
SYSCTL = "/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal"


def out(o):
    sys.stdout.write(json.dumps(o) + "\n")
    sys.stdout.flush()


def run(cmd, inp=None):
    r = subprocess.run(cmd, input=inp, capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout, r.stderr


def under_home(path, home):
    return os.path.realpath(path).startswith(os.path.realpath(home) + os.sep)


def kill_all():
    for p in list(procs.values()):
        if p.poll() is None:
            p.terminate()
    for p in list(procs.values()):
        try:
            p.wait(3)
        except Exception:
            p.kill()
    procs.clear()


def handle(req, uid, gid, home):
    op = req.get("op")
    if op == "ping":
        return {}
    if op == "nft_backup":
        if not under_home(req["path"], home):
            return {"ok": False, "err": "path outside home"}
        rc, so, se = run(["nft", "list", "ruleset"])
        if rc:
            return {"ok": False, "err": se}
        with open(req["path"], "w") as f:
            f.write(so)
        os.chown(req["path"], uid, gid)
        return {}
    if op == "nft_apply":
        rc, so, se = run(["nft", "-f", "-"], req["script"])
        return {} if rc == 0 else {"ok": False, "err": se.strip()}
    if op == "nft_delete":
        run(["nft", "delete", "table", "inet", req["table"]])
        return {}
    if op == "nft_restore":
        if not under_home(req["path"], home):
            return {"ok": False, "err": "path outside home"}
        data = open(req["path"]).read()
        rc, so, se = run(["nft", "-f", "-"], "flush ruleset\n" + data)
        return {} if rc == 0 else {"ok": False, "err": se.strip()}
    if op == "sysctl_liberal":
        try:
            old = open(SYSCTL).read().strip()
            if req.get("value") is not None:
                open(SYSCTL, "w").write(str(req["value"]))
            return {"old": old}
        except OSError as e:
            return {"ok": False, "err": str(e)}
    if op == "start":
        argv, log = req["argv"], req["log"]
        if os.path.basename(argv[0]) != "nfqws2":
            return {"ok": False, "err": "only nfqws2 may be started"}
        if not under_home(log, home):
            return {"ok": False, "err": "log outside home"}
        lf = open(log, "ab")
        p = subprocess.Popen(argv, stdout=lf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                             start_new_session=True)
        procs[p.pid] = p
        return {"pid": p.pid}
    if op == "alive":
        p = procs.get(req["pid"])
        return {"alive": bool(p and p.poll() is None), "rc": None if not p else p.poll()}
    if op == "stop":
        p = procs.pop(req["pid"], None)
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(3)
            except Exception:
                p.kill()
        return {}
    return {"ok": False, "err": f"unknown op {op}"}


def main():
    uid, gid, home = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
    for line in sys.stdin:
        try:
            req = json.loads(line)
            res = handle(req, uid, gid, home)
            res.setdefault("ok", True)
        except Exception as e:  # noqa
            res = {"ok": False, "err": repr(e)}
        res["id"] = req.get("id") if isinstance(req, dict) else None
        out(res)
    kill_all()


if __name__ == "__main__":
    main()
