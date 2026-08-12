# -*- coding: utf-8 -*-
r"""
watchdump2.py — 隱蔽版守護 dumper (管理員執行)。
偵測到 TWClient → 以【唯讀】權限開 handle → 枚舉所有記憶體區段 →
dump 出可能含「解壓碼 / rdata / 結構堆積」的區段(跳過超大素材區) →
寫 manifest(每區段 base/size/prot/type/entropy/已知字串) → 立刻關 handle 退出。
盡量縮短 handle 存活時間，避免被反作弊週期掃描殺掉遊戲。

用法(管理員): python watchdump2.py
"""
import sys
import os
import time
import math
import ctypes

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import memtool

DUMPS = os.path.normpath(os.path.join(HERE, "..", "dumps"))
OUTDIR = os.path.join(DUMPS, "regions")
LOG = os.path.join(DUMPS, "watchdump2.log")
TARGETS = ["twclient", "yongnian", "182tian", "182天"]
WAIT = 900
MAX_REGION = 0x4000000      # 單區段最多 dump 64MB (跳過更大的素材/surface)
MAX_TOTAL = 0x18000000      # 總量上限 ~384MB
READONLY = memtool.PROCESS_QUERY_INFORMATION | memtool.PROCESS_VM_READ

KNOWN = [b"virtSurf", b"Access Violation", b"Sprite", b"Client Version",
         b"ws2_32", b"ddraw", b"DDERR", b".xml", b"lineage", b"Lineage",
         b"Socket", b"user32", b"gdi32", b"WindowMode", b"MSVCR"]


def logw(f, m):
    f.write("%.3f  %s\n" % (time.time(), m))
    f.flush()


def entropy(b):
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    n = len(b)
    e = 0.0
    for x in c:
        if x:
            p = x / n
            e -= p * math.log2(p)
    return e


def is_game(n):
    n = n.lower()
    return any(t in n for t in TARGETS) or (n.endswith(".bin") and n != "swap.bin")


def enum_procs():
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


def prot_ex(p):
    return (p & 0xFF) in (0x10, 0x20, 0x40, 0x80)


def capture(pid, f):
    os.makedirs(OUTDIR, exist_ok=True)
    p = memtool.Process.open(pid, access=READONLY)
    logw(f, "opened READ-ONLY handle pid=%d" % pid)
    regs = p.regions()          # 所有 committed 可讀區段
    logw(f, "regions=%d" % len(regs))
    man = open(os.path.join(OUTDIR, "manifest.txt"), "w", encoding="utf-8")
    man.write("base\tsize\tprot\ttype\tentropy64k\texec\tdumped\tknown\n")
    total = 0
    t_start = time.time()
    for r in sorted(regs, key=lambda x: x["base"]):
        base, size, prot, typ = r["base"], r["size"], r["protect"], r["type"]
        smp = p.read(base, min(0x10000, size)) or b""
        ent = entropy(smp)
        hits = ",".join(sorted(set(k.decode("latin1") for k in KNOWN if k in smp)))
        ex = prot_ex(prot)
        dumped = ""
        # dump 條件: 可執行(碼)  或  含已知字串(rdata)  或  私有/image 且不超大
        want = ex or hits or (typ in (0x20000, 0x1000000) and size <= MAX_REGION)
        if want and size <= MAX_REGION and total < MAX_TOTAL:
            data = p.read(base, size)
            if data:
                if len(data) < size:
                    data = data + b"\x00" * (size - len(data))
                fn = os.path.join(OUTDIR, "mem_%08X.bin" % base)
                with open(fn, "wb") as o:
                    o.write(data)
                total += size
                dumped = "Y"
        man.write("0x%08X\t0x%08X\t0x%02X\t0x%X\t%.2f\t%s\t%s\t%s\n"
                  % (base, size, prot, typ, ent, "X" if ex else "-", dumped, hits))
    man.close()
    p.close()
    logw(f, "closed handle. dumped total=0x%X (%.1f MB) in %.1fs -> %s"
         % (total, total / 1048576, time.time() - t_start, OUTDIR))


def main():
    os.makedirs(DUMPS, exist_ok=True)
    f = open(LOG, "a", encoding="utf-8", buffering=1)
    admin = False
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass
    logw(f, "==== watchdump2 start admin=%s ====" % admin)
    t0 = time.time()
    while time.time() - t0 < WAIT:
        try:
            hit = next(((pid, n) for pid, n in enum_procs() if is_game(n)), None)
        except Exception as e:
            logw(f, "enum fail %r" % e)
            time.sleep(0.3)
            continue
        if hit:
            pid, name = hit
            logw(f, "DETECT %s pid=%d (elapsed %.1fs)" % (name, pid, time.time() - t0))
            try:
                capture(pid, f)
                logw(f, "完成，結束。")
            except Exception as e:
                logw(f, "capture fail %r" % e)
            f.close()
            return
        time.sleep(0.02)
    logw(f, "timeout")
    f.close()


if __name__ == "__main__":
    main()
