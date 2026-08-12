# -*- coding: utf-8 -*-
r"""
watchdump.py — 獨立、需以【系統管理員】執行的守護 dumper。
行程內緊迴圈(20ms)偵測天堂客戶端，一出現就立刻 dump 脫殼映像；
並記錄啟動器生出的所有相關行程名與存活秒數。全程寫 log 檔(即時 flush)。

用法(管理員): python watchdump.py
"""
import sys
import os
import time
import ctypes

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import memtool

DUMPS = os.path.normpath(os.path.join(HERE, "..", "dumps"))
LOG = os.path.join(DUMPS, "watchdump.log")
OUT = os.path.join(DUMPS, "TWClient_unpacked.dump")
TARGETS = ["twclient", "yongnian", "182tian", "182天"]
WAIT = 900

_KEYS = ("lin", "tw", "yong", "login", "182", "npk", "npg",
         "game", "guard", "oreans", "xprot", "npx", "shell")


def logw(f, m):
    f.write("%.3f  %s\n" % (time.time(), m))
    f.flush()


def is_game(n):
    n = n.lower()
    if any(t in n for t in TARGETS):
        return True
    if n.endswith(".bin") and n not in ("swap.bin",):
        return True
    return False


def enum():
    k32 = memtool.k32
    snap = k32.CreateToolhelp32Snapshot(memtool.TH32CS_SNAPPROCESS, 0)
    pe = memtool.PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(memtool.PROCESSENTRY32W)
    out = []
    ok = k32.Process32FirstW(snap, ctypes.byref(pe))
    while ok:
        out.append((pe.th32ProcessID, pe.szExeFile))
        ok = k32.Process32NextW(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    return out


def do_dump(pid, f):
    p = memtool.Process.open(pid)
    m = p.main_module()
    if not m:
        logw(f, "無主模組 pid=%d" % pid)
        p.close()
        return False
    base, size = m["base"], m["size"]
    logw(f, "attach ok base=0x%08X size=0x%X name=%s" % (base, size, m["name"]))
    ok_c = zero_c = 0
    with open(OUT, "wb") as o:
        off = 0
        CH = 0x100000
        while off < size:
            n = min(CH, size - off)
            b = p.read(base + off, n)
            if b is None:
                b = b"\x00" * n
                zero_c += 1
            else:
                if len(b) < n:
                    b = b + b"\x00" * (n - len(b))
                ok_c += 1
            o.write(b)
            off += n
    logw(f, "DUMP DONE -> %s size=0x%X ok_chunks=%d zero_chunks=%d" %
         (OUT, size, ok_c, zero_c))
    p.close()
    return True


def main():
    os.makedirs(DUMPS, exist_ok=True)
    f = open(LOG, "a", encoding="utf-8", buffering=1)
    admin = False
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass
    logw(f, "==== watchdump start admin=%s wait=%ds ====" % (admin, WAIT))
    if not admin:
        logw(f, "警告: 非管理員，OpenProcess 可能被拒")
    t0 = time.time()
    seen = set()
    while time.time() - t0 < WAIT:
        try:
            procs = enum()
        except Exception as e:
            logw(f, "enum fail: %r" % e)
            time.sleep(0.2)
            continue
        for pid, name in procs:
            if is_game(name):
                logw(f, "DETECT game pid=%d name=%s (elapsed %.1fs) -> dumping"
                     % (pid, name, time.time() - t0))
                try:
                    if do_dump(pid, f):
                        logw(f, "完成，結束。")
                        f.close()
                        return
                except Exception as e:
                    logw(f, "dump fail: %r (稍後重試)" % e)
        # 記錄新出現的相關行程
        for pid, name in procs:
            k = name.lower()
            if k not in seen and (k.endswith(".bin") or any(x in k for x in _KEYS)):
                seen.add(k)
                logw(f, "new proc: %s (pid %d)" % (name, pid))
        time.sleep(0.02)
    logw(f, "timeout, 未偵測到遊戲")
    f.close()


if __name__ == "__main__":
    main()
