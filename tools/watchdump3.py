# -*- coding: utf-8 -*-
r"""
watchdump3.py — 等初始化完成再快照 (管理員執行)。
偵測 TWClient → 用 Toolhelp【輪詢模組清單】(不開 handle, 隱蔽) 等殼解壓完、
真 DLL(user32/gdi32/ddraw) 載入 → 再開一次唯讀 handle、快照所有區段、立刻關閉。
擷取後自動驗證碼區是否已解密(數 x86 函數開頭)。

用法(管理員): python watchdump3.py
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
OUTDIR = os.path.join(DUMPS, "regions3")
LOG = os.path.join(DUMPS, "watchdump3.log")
TARGETS = ["twclient", "yongnian", "182tian", "182天"]
WAIT = 3600             # 守候 1 小時
MAX_REGION = 0x4000000
MAX_TOTAL = 0x20000000
READONLY = memtool.PROCESS_QUERY_INFORMATION | memtool.PROCESS_VM_READ
READY_DLLS = ("user32.dll", "gdi32.dll", "ddraw.dll", "d3d9.dll", "ijl15.dll")
READY_MODCOUNT = 15
INIT_TIMEOUT = 30.0     # 等初始化最多 30s
SETTLE = 1.5            # 就緒後再等 1.5s
DECRYPT_WAIT = 40.0     # 等碼解密最多 40s (持續取樣 0x401000 函數開頭數)
PLAYER_PTR = 0x00C2D2B8 # 角色物件指標(≠0 表示已進場)
CNT_A = 0x00C2D2E0      # 實體清單A 數量
INWORLD_WAIT = 180.0    # 等使用者進場最多 3 分鐘

KNOWN = [b"virtSurf", b"Access Violation", b"Sprite", b"Client Version",
         b"ddraw", b"DDERR", b".xml", b"Lineage", b"Socket", b"WindowMode"]


def logw(f, m):
    f.write("%.3f  %s\n" % (time.time(), m))
    f.flush()
    print(m, flush=True)


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


def count_prologues(b):
    n = 0
    for i in range(len(b) - 2):
        if b[i] == 0x55 and b[i + 1] == 0x8B and b[i + 2] == 0xEC:
            n += 1
    return n


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


def enum_modules(pid):
    """Toolhelp 模組列舉 — 不需 OpenProcess handle。"""
    k32 = memtool.k32
    snap = k32.CreateToolhelp32Snapshot(
        memtool.TH32CS_SNAPMODULE | memtool.TH32CS_SNAPMODULE32, pid)
    if snap in (-1, 0xFFFFFFFF, None):
        return []
    me = memtool.MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(memtool.MODULEENTRY32W)
    out = []
    ok = k32.Module32FirstW(snap, ctypes.byref(me))
    while ok:
        out.append(me.szModule)
        ok = k32.Module32NextW(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
    return out


def wait_ready(pid, f):
    """輪詢模組清單直到初始化完成。回傳 True/False(行程死了)。"""
    t0 = time.time()
    last = -1
    while time.time() - t0 < INIT_TIMEOUT:
        mods = enum_modules(pid)
        if not mods:
            # 行程可能已結束
            if pid not in [p for p, _ in enum_procs()]:
                logw(f, "行程消失(初始化中)")
                return False
            time.sleep(0.2)
            continue
        low = [m.lower() for m in mods]
        if len(mods) != last:
            has = [d for d in READY_DLLS if d in low]
            logw(f, "  模組數=%d ready_dlls=%s" % (len(mods), has))
            last = len(mods)
        if len(mods) >= READY_MODCOUNT or any(d in low for d in READY_DLLS):
            logw(f, "初始化就緒 (模組數=%d)" % len(mods))
            return True
        time.sleep(0.25)
    logw(f, "初始化等逾時, 仍嘗試擷取")
    return True


def wait_decrypt(pid, f):
    """短命唯讀 handle 反覆取樣碼區, 觀察 x86 函數開頭何時出現(=已解密)。"""
    t0 = time.time()
    while time.time() - t0 < DECRYPT_WAIT:
        if pid not in [pp for pp, _ in enum_procs()]:
            logw(f, "解密等待中行程死亡")
            return False
        try:
            p = memtool.Process.open(pid, access=READONLY)
        except Exception as e:
            logw(f, "open 失敗 %r" % e)
            time.sleep(1.0)
            continue
        best = 0
        for a in (0x401000, 0x401000 + 0x100000, 0x401000 + 0x300000, 0xC90000):
            smp = p.read(a, 0x10000) or b""
            best = max(best, count_prologues(smp))
        p.close()          # 立刻關 handle
        logw(f, "  碼區函數開頭取樣 max=%d (elapsed %.1fs)" % (best, time.time() - t0))
        if best >= 30:
            logw(f, "碼已解密! 立即完整擷取")
            return True
        time.sleep(1.2)
    logw(f, "等碼解密逾時, 仍best-effort擷取")
    return True


def wait_inworld(pid, f):
    """碼解密後, 輪詢角色指標直到≠0 (使用者進場)。短命唯讀 handle。"""
    t0 = time.time()
    last = -1
    while time.time() - t0 < INWORLD_WAIT:
        if pid not in [pp for pp, _ in enum_procs()]:
            logw(f, "等進場時行程死亡")
            return False
        try:
            p = memtool.Process.open(pid, access=READONLY)
            ptr = p.read_val(PLAYER_PTR, "u32")
            cnt = p.read_val(CNT_A, "u32")
            p.close()
        except Exception as e:
            logw(f, "進場輪詢 read 失敗 %r" % e)
            time.sleep(1.5)
            continue
        if ptr:
            logw(f, "★角色已進場! player=0x%08X 實體數=%s → 擷取活記憶體" % (ptr, cnt))
            return True
        if cnt != last:
            logw(f, "  等待進場中(角色指標=0, 實體數=%s)…" % cnt)
            last = cnt
        time.sleep(1.5)
    logw(f, "等進場逾時, 仍擷取")
    return True


def capture(pid, f):
    os.makedirs(OUTDIR, exist_ok=True)
    p = memtool.Process.open(pid, access=READONLY)
    logw(f, "opened READ-ONLY handle pid=%d" % pid)
    regs = p.regions()
    man = open(os.path.join(OUTDIR, "manifest.txt"), "w", encoding="utf-8")
    man.write("base\tsize\tprot\ttype\tent64k\texec\tprologues\tdumped\tknown\n")
    total = 0
    best = None
    for r in sorted(regs, key=lambda x: x["base"]):
        base, size, prot, typ = r["base"], r["size"], r["protect"], r["type"]
        smp = p.read(base, min(0x10000, size)) or b""
        ent = entropy(smp)
        ex = (prot & 0xFF) in (0x10, 0x20, 0x40, 0x80)
        pro = count_prologues(smp) if ex else 0
        hits = ",".join(sorted(set(k.decode("latin1") for k in KNOWN if k in smp)))
        dumped = ""
        want = ex or hits or (typ in (0x20000, 0x1000000) and size <= MAX_REGION)
        if want and size <= MAX_REGION and total < MAX_TOTAL:
            data = p.read(base, size)
            if data:
                if len(data) < size:
                    data = data + b"\x00" * (size - len(data))
                with open(os.path.join(OUTDIR, "mem_%08X.bin" % base), "wb") as o:
                    o.write(data)
                total += size
                dumped = "Y"
                if ex and pro > (best[1] if best else 0):
                    best = (base, pro, size)
        man.write("0x%08X\t0x%08X\t0x%02X\t0x%X\t%.2f\t%s\t%d\t%s\t%s\n"
                  % (base, size, prot, typ, ent, "X" if ex else "-", pro, dumped, hits))
    man.close()
    p.close()
    logw(f, "closed handle. dumped=%.1fMB regions=%d" % (total / 1048576, len(regs)))
    if best:
        logw(f, ">>> 最像解密碼的可執行區: base=0x%08X prologues=%d size=0x%X"
             % (best[0], best[1], best[2]))
    else:
        logw(f, ">>> 警告: 沒有任何可執行區含 x86 函數開頭 (碼可能仍未解密)")


def main():
    os.makedirs(DUMPS, exist_ok=True)
    f = open(LOG, "a", encoding="utf-8", buffering=1)
    admin = False
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass
    logw(f, "==== watchdump3 start admin=%s ====" % admin)
    t0 = time.time()
    while time.time() - t0 < WAIT:
        hit = next(((pid, n) for pid, n in enum_procs() if is_game(n)), None)
        if hit:
            pid, name = hit
            logw(f, "DETECT %s pid=%d — 等初始化…" % (name, pid))
            if not wait_ready(pid, f):
                logw(f, "此次行程夭折, 繼續守候下一次")
                time.sleep(1.0)
                continue
            time.sleep(SETTLE)
            # 確認還活著
            if pid not in [p for p, _ in enum_procs()]:
                logw(f, "擷取前行程已死, 繼續守候")
                continue
            # 等碼解密(持續取樣); 行程中途死就繼續守候
            if not wait_decrypt(pid, f):
                time.sleep(1.0)
                continue
            # 等使用者進場(角色指標≠0)才擷取, 才有活的角色/怪物資料
            if not wait_inworld(pid, f):
                time.sleep(1.0)
                continue
            if pid not in [p for p, _ in enum_procs()]:
                logw(f, "擷取前行程已死, 繼續守候")
                continue
            try:
                capture(pid, f)
                logw(f, "完成，結束。")
            except Exception as e:
                logw(f, "capture fail %r" % e)
            f.close()
            return
        time.sleep(0.05)
    logw(f, "timeout")
    f.close()


if __name__ == "__main__":
    main()
