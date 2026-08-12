# -*- coding: utf-8 -*-
r"""
memtool.py — 天堂客戶端記憶體逆向 / 讀取工具 (純 ctypes, 免安裝套件)

用途:
  1. 附加遊戲行程、枚舉模組、走訪記憶體區段
  2. 讀 / 寫記憶體 (u8/u16/u32/i16/i32/f32/f64/指標/位元組)
  3. AOB (byte pattern) 掃描 —— 找程式碼特徵
  4. value-scanner (Cheat Engine 式 first/next scan) —— 找 角色座標 / HP / 怪物欄位
  5. dump 模組映像到檔案 —— 脫殼後給 Ghidra 分析

CLI 範例:
  py memtool.py attach TWClient
  py memtool.py regions TWClient --image           # 只列 image 區段
  py memtool.py dump TWClient --out ..\dumps\tw.bin # 落地主模組映像 (脫殼後執行)
  py memtool.py scan TWClient --type i32 --value 32768      # 首次掃描
  #  <在遊戲裡移動角色，座標改變後>
  py memtool.py next TWClient --type i32 --value 32770      # 用新值篩選
  py memtool.py next TWClient --type i32 --changed          # 或用「變了」篩選
  py memtool.py read TWClient 0x0AB3C120 --type i32 --count 8
  py memtool.py aob  TWClient --pattern "8B 0D ?? ?? ?? ?? 89 41 04"
  py memtool.py watch TWClient 0x0AB3C120 --type i32        # 持續監看

掃描狀態存在  <project>\dumps\scan_state.json ，可跨次 next 精修。
只讀取，不寫入 (除非用 poke 子指令)。純自用私服客戶端。
"""

import sys
import os
import json
import time
import struct
import ctypes
from ctypes import wintypes

# ---------------------------------------------------------------------------
# Win32 API 綁定
# ---------------------------------------------------------------------------
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_ALL_READ = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPPROCESS = 0x00000002

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
# 可讀的保護旗標
_READABLE = (0x02, 0x04, 0x08, 0x20, 0x40, 0x80)  # R, RW, WC, ER, ERW, ERWC


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    # 由 64-bit 呼叫端查詢 → 用 64-bit 版；32-bit 目標位址仍 < 4GB
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("__alignment2", wintypes.DWORD),
    ]


k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong,
                               ctypes.POINTER(MEMORY_BASIC_INFORMATION64), ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = wintypes.BOOL

# type 名 -> (struct fmt, size)
TYPES = {
    "u8": ("<B", 1), "i8": ("<b", 1),
    "u16": ("<H", 2), "i16": ("<h", 2),
    "u32": ("<I", 4), "i32": ("<i", 4),
    "u64": ("<Q", 8), "i64": ("<q", 8),
    "f32": ("<f", 4), "f64": ("<d", 8),
}

SCAN_STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "..", "dumps", "scan_state.json")


# ---------------------------------------------------------------------------
class Process:
    def __init__(self, handle, pid):
        self.h = handle
        self.pid = pid

    # 預設【唯讀】(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ) —— 跟 LiTo 一樣隱蔽,
    # 避免客戶端保護掃到「可注入」handle 而殺遊戲。要寫入時明確傳 access。
    @classmethod
    def open(cls, ident, access=PROCESS_QUERY_INFORMATION | PROCESS_VM_READ):
        pid = ident if isinstance(ident, int) else find_pid(ident)
        if not pid:
            raise RuntimeError("找不到行程: %s" % ident)
        h = k32.OpenProcess(access, False, pid)
        if not h:
            # 降級成唯讀
            h = k32.OpenProcess(PROCESS_ALL_READ, False, pid)
        if not h:
            raise RuntimeError("OpenProcess 失敗 pid=%d err=%d (試以系統管理員執行)"
                               % (pid, ctypes.get_last_error()))
        return cls(h, pid)

    def close(self):
        if self.h:
            k32.CloseHandle(self.h)
            self.h = None

    # ---- 模組 ----
    def modules(self):
        out = []
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid)
        if snap == wintypes.HANDLE(-1).value or snap == -1:
            return out
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)
        ok = k32.Module32FirstW(snap, ctypes.byref(me))
        while ok:
            out.append({
                "name": me.szModule,
                "base": me.modBaseAddr or 0,
                "size": me.modBaseSize,
                "path": me.szExePath,
            })
            ok = k32.Module32NextW(snap, ctypes.byref(me))
        k32.CloseHandle(snap)
        return out

    def main_module(self):
        mods = self.modules()
        return mods[0] if mods else None

    def module(self, name):
        name = name.lower()
        for m in self.modules():
            if m["name"].lower() == name or m["name"].lower().startswith(name):
                return m
        return None

    # ---- 區段 ----
    def regions(self, image_only=False, writable_only=False):
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION64()
        out = []
        max_addr = 0x7FFFFFFF0000
        while addr < max_addr:
            r = k32.VirtualQueryEx(self.h, addr, ctypes.byref(mbi), ctypes.sizeof(mbi))
            if r == 0:
                break
            size = mbi.RegionSize
            if size == 0:
                break
            if (mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in _READABLE
                    and not (mbi.Protect & PAGE_GUARD)):
                if not image_only or mbi.Type == MEM_IMAGE:
                    if not writable_only or (mbi.Protect & 0xFF) in (0x04, 0x08, 0x40, 0x80):
                        out.append({
                            "base": mbi.BaseAddress, "size": size,
                            "protect": mbi.Protect, "type": mbi.Type,
                        })
            addr = mbi.BaseAddress + size
        return out

    # ---- 讀 ----
    def read(self, addr, size):
        buf = (ctypes.c_char * size)()
        got = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(self.h, addr, buf, size, ctypes.byref(got))
        if not ok:
            return None
        return bytes(buf[:got.value])

    def read_val(self, addr, tname):
        fmt, sz = TYPES[tname]
        b = self.read(addr, sz)
        if not b or len(b) < sz:
            return None
        return struct.unpack(fmt, b)[0]

    def read_ptr(self, addr):
        return self.read_val(addr, "u32")   # 32-bit 目標

    def write(self, addr, data):
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        wrote = ctypes.c_size_t(0)
        ok = k32.WriteProcessMemory(self.h, addr, buf, len(data), ctypes.byref(wrote))
        return bool(ok)

    def write_val(self, addr, tname, value):
        fmt, _ = TYPES[tname]
        return self.write(addr, struct.pack(fmt, value))


# ---------------------------------------------------------------------------
def find_pid(name):
    name_l = name.lower()
    cands = []
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    ok = k32.Process32FirstW(snap, ctypes.byref(pe))
    while ok:
        exe = pe.szExeFile.lower()
        if exe == name_l or exe == name_l + ".exe" or exe == name_l + ".bin" \
                or exe.startswith(name_l):
            cands.append((pe.th32ProcessID, pe.szExeFile))
        ok = k32.Process32NextW(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    if not cands:
        return None
    if len(cands) > 1:
        sys.stderr.write("多個符合行程: %s，用第一個 (可改用 pid)\n" % cands)
    return cands[0][0]


def parse_pattern(pat):
    """'8B 0D ?? ?? ?? ?? 89' -> (bytes, mask)."""
    toks = pat.replace(",", " ").split()
    bs = bytearray()
    mask = bytearray()
    for t in toks:
        if t in ("??", "?", "*", "xx"):
            bs.append(0)
            mask.append(0)
        else:
            bs.append(int(t, 16))
            mask.append(1)
    return bytes(bs), bytes(mask)


def scan_bytes(data, pat, mask):
    n, m = len(data), len(pat)
    res = []
    if m == 0:
        return res
    first = pat[0]
    fm = mask[0]
    i = 0
    while i <= n - m:
        if fm and data[i] != first:
            i += 1
            continue
        j = 1
        while j < m and (not mask[j] or data[i + j] == pat[j]):
            j += 1
        if j == m:
            res.append(i)
        i += 1
    return res


# ---------------------------------------------------------------------------
#  value scanner
# ---------------------------------------------------------------------------
def _iter_scan_regions(proc, image_only, writable_only, max_region=0x4000000):
    for r in proc.regions(image_only=image_only, writable_only=writable_only):
        if r["size"] > max_region:
            # 大區段分塊，避免一次讀太多
            off = 0
            while off < r["size"]:
                chunk = min(max_region, r["size"] - off)
                yield r["base"] + off, chunk
                off += chunk
        else:
            yield r["base"], r["size"]


def first_scan(proc, tname, value, align=None, image_only=False, writable_only=True):
    fmt, sz = TYPES[tname]
    target = struct.pack(fmt, value)
    if align is None:
        align = sz if tname not in ("f32", "f64") else 4
    hits = []
    for base, size in _iter_scan_regions(proc, image_only, writable_only):
        data = proc.read(base, size)
        if not data:
            continue
        # 對齊掃描
        i = 0
        limit = len(data) - sz
        step = align if align else 1
        # 用 bytes.find 加速非對齊；對齊則自行走
        if step == 1:
            idx = data.find(target)
            while idx != -1:
                hits.append(base + idx)
                idx = data.find(target, idx + 1)
        else:
            while i <= limit:
                if data[i:i + sz] == target:
                    hits.append(base + i)
                i += step
        if len(hits) > 5_000_000:
            sys.stderr.write("命中過多，停止 (請用更獨特的值)\n")
            break
    return hits


def next_scan(proc, tname, addrs, mode, value=None):
    """mode: 'value'|'changed'|'unchanged'|'inc'|'dec'. addrs: [(addr, oldval)]."""
    fmt, sz = TYPES[tname]
    out = []
    for addr, old in addrs:
        cur = proc.read_val(addr, tname)
        if cur is None:
            continue
        keep = False
        if mode == "value":
            keep = (cur == value)
        elif mode == "changed":
            keep = (cur != old)
        elif mode == "unchanged":
            keep = (cur == old)
        elif mode == "inc":
            keep = (cur > old)
        elif mode == "dec":
            keep = (cur < old)
        if keep:
            out.append((addr, cur))
    return out


def save_state(tname, addrs):
    os.makedirs(os.path.dirname(SCAN_STATE), exist_ok=True)
    with open(SCAN_STATE, "w") as f:
        json.dump({"type": tname, "addrs": [[a, v] for a, v in addrs]}, f)


def load_state():
    with open(SCAN_STATE) as f:
        d = json.load(f)
    return d["type"], [(a, v) for a, v in d["addrs"]]


# ---------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------
def _fmt_hex(a):
    return "0x%08X" % a


def cmd_attach(args):
    p = Process.open(_ident(args))
    m = p.main_module()
    print("PID       :", p.pid)
    if m:
        print("主模組    : %s  base=%s  size=0x%X (%.1f MB)"
              % (m["name"], _fmt_hex(m["base"]), m["size"], m["size"] / 1048576))
    mods = p.modules()
    print("模組數    :", len(mods))
    for md in mods[:40]:
        print("  %-24s %s  0x%08X" % (md["name"], _fmt_hex(md["base"]), md["size"]))
    p.close()


def cmd_regions(args):
    p = Process.open(_ident(args))
    regs = p.regions(image_only=args.image, writable_only=args.writable)
    total = sum(r["size"] for r in regs)
    print("可讀區段 %d 個，合計 %.1f MB%s"
          % (len(regs), total / 1048576,
             "  (image only)" if args.image else ""))
    for r in regs[:200]:
        print("  %s  size=0x%08X  prot=0x%X  type=0x%X"
              % (_fmt_hex(r["base"]), r["size"], r["protect"], r["type"]))
    p.close()


def cmd_dump(args):
    p = Process.open(_ident(args))
    if args.module:
        m = p.module(args.module)
    else:
        m = p.main_module()
    if not m:
        print("找不到模組")
        return
    base, size = m["base"], m["size"]
    out = args.out or os.path.join(os.path.dirname(SCAN_STATE),
                                   "%s_%08X.dump" % (m["name"], base))
    print("dump %s base=%s size=0x%X -> %s" % (m["name"], _fmt_hex(base), size, out))
    got = 0
    with open(out, "wb") as f:
        off = 0
        CH = 0x100000
        while off < size:
            n = min(CH, size - off)
            b = p.read(base + off, n)
            if b is None:
                # 該頁不可讀，補零維持對齊
                b = b"\x00" * n
            elif len(b) < n:
                b = b + b"\x00" * (n - len(b))
            f.write(b)
            got += sum(1 for _ in b if True) and n
            off += n
    print("完成，寫出 0x%X bytes。可用 Ghidra 以 base 0x%X 匯入 (raw, x86)。"
          % (size, base))
    print("提示: 若為脫殼映像，Ghidra 匯入時語言選 x86:LE:32:default，Image Base 設 %s"
          % _fmt_hex(base))
    p.close()


def cmd_scan(args):
    p = Process.open(_ident(args))
    value = _parse_value(args.type, args.value)
    t0 = time.time()
    hits = first_scan(p, args.type, value, align=args.step,
                      image_only=args.image, writable_only=not args.all_mem)
    pairs = [(a, value) for a in hits]
    save_state(args.type, pairs)
    print("首次掃描 type=%s value=%s → 命中 %d 個 (%.1fs)"
          % (args.type, args.value, len(hits), time.time() - t0))
    for a, v in pairs[:40]:
        print("  ", _fmt_hex(a), "=", v)
    if len(hits) > 40:
        print("  ... 共 %d，已存 scan_state.json，移動角色後用 next 精修" % len(hits))
    p.close()


def cmd_next(args):
    p = Process.open(_ident(args))
    tname, addrs = load_state()
    mode = "value"
    value = None
    if args.changed:
        mode = "changed"
    elif args.unchanged:
        mode = "unchanged"
    elif args.inc:
        mode = "inc"
    elif args.dec:
        mode = "dec"
    else:
        value = _parse_value(tname, args.value)
    res = next_scan(p, tname, addrs, mode, value)
    save_state(tname, res)
    print("next (%s) → 剩 %d 個" % (mode, len(res)))
    for a, v in res[:60]:
        print("  ", _fmt_hex(a), "=", v)
    p.close()


def cmd_read(args):
    p = Process.open(_ident(args))
    addr = int(args.addr, 0)
    fmt, sz = TYPES[args.type]
    print("讀 %s type=%s count=%d" % (_fmt_hex(addr), args.type, args.count))
    for i in range(args.count):
        a = addr + i * sz
        v = p.read_val(a, args.type)
        extra = ""
        if args.type in ("u32", "i32") and v is not None and 0x10000 < (v & 0xFFFFFFFF) < 0x7FFFFFFF:
            extra = "  (可能是指標)"
        print("  %s : %s%s" % (_fmt_hex(a), v, extra))
    p.close()


def cmd_aob(args):
    p = Process.open(_ident(args))
    pat, mask = parse_pattern(args.pattern)
    print("AOB 掃描 (%d bytes pattern)..." % len(pat))
    total = 0
    for base, size in _iter_scan_regions(p, args.image, False):
        data = p.read(base, size)
        if not data:
            continue
        for off in scan_bytes(data, pat, mask):
            print("  hit:", _fmt_hex(base + off))
            total += 1
            if total >= 200:
                print("  (>=200，停止)")
                p.close()
                return
    print("共 %d 命中" % total)
    p.close()


def cmd_watch(args):
    p = Process.open(_ident(args))
    addr = int(args.addr, 0)
    print("監看 %s type=%s (Ctrl+C 停)" % (_fmt_hex(addr), args.type))
    last = object()
    try:
        while True:
            v = p.read_val(addr, args.type)
            if v != last:
                print("  %.2f  %s" % (time.time(), v))
                last = v
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    p.close()


def cmd_poke(args):
    p = Process.open(_ident(args))
    addr = int(args.addr, 0)
    value = _parse_value(args.type, args.value)
    ok = p.write_val(addr, args.type, value)
    print("寫入 %s = %s : %s" % (_fmt_hex(addr), value, "OK" if ok else "失敗"))
    p.close()


def _ident(args):
    t = args.target
    if t.isdigit():
        return int(t)
    return t


def _parse_value(tname, s):
    if tname in ("f32", "f64"):
        return float(s)
    return int(s, 0)


def build_parser():
    import argparse
    ap = argparse.ArgumentParser(description="天堂客戶端記憶體工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_target(sp):
        sp.add_argument("target", help="行程名(如 TWClient) 或 PID")

    sp = sub.add_parser("attach"); add_target(sp); sp.set_defaults(fn=cmd_attach)

    sp = sub.add_parser("regions"); add_target(sp)
    sp.add_argument("--image", action="store_true", help="只列 image 型區段")
    sp.add_argument("--writable", action="store_true", help="只列可寫區段")
    sp.set_defaults(fn=cmd_regions)

    sp = sub.add_parser("dump"); add_target(sp)
    sp.add_argument("--module", help="模組名 (預設主模組)")
    sp.add_argument("--out", help="輸出檔")
    sp.set_defaults(fn=cmd_dump)

    sp = sub.add_parser("scan"); add_target(sp)
    sp.add_argument("--type", default="i32", choices=list(TYPES))
    sp.add_argument("--value", required=True)
    sp.add_argument("--step", type=int, default=None, help="對齊步進 (預設=型別大小)")
    sp.add_argument("--image", action="store_true", help="只掃 image 區段")
    sp.add_argument("--all-mem", action="store_true", help="連唯讀區也掃 (預設只掃可寫)")
    sp.set_defaults(fn=cmd_scan)

    sp = sub.add_parser("next"); add_target(sp)
    sp.add_argument("--value", help="用新值篩選")
    sp.add_argument("--changed", action="store_true")
    sp.add_argument("--unchanged", action="store_true")
    sp.add_argument("--inc", action="store_true")
    sp.add_argument("--dec", action="store_true")
    sp.set_defaults(fn=cmd_next)

    sp = sub.add_parser("read"); add_target(sp)
    sp.add_argument("addr")
    sp.add_argument("--type", default="i32", choices=list(TYPES))
    sp.add_argument("--count", type=int, default=1)
    sp.set_defaults(fn=cmd_read)

    sp = sub.add_parser("aob"); add_target(sp)
    sp.add_argument("--pattern", required=True, help='如 "8B 0D ?? ?? ?? ?? 89"')
    sp.add_argument("--image", action="store_true")
    sp.set_defaults(fn=cmd_aob)

    sp = sub.add_parser("watch"); add_target(sp)
    sp.add_argument("addr")
    sp.add_argument("--type", default="i32", choices=list(TYPES))
    sp.add_argument("--interval", type=float, default=0.2)
    sp.set_defaults(fn=cmd_watch)

    sp = sub.add_parser("poke"); add_target(sp)
    sp.add_argument("addr")
    sp.add_argument("--type", default="i32", choices=list(TYPES))
    sp.add_argument("--value", required=True)
    sp.set_defaults(fn=cmd_poke)

    return ap


def main():
    ap = build_parser()
    args = ap.parse_args()
    try:
        args.fn(args)
    except RuntimeError as e:
        print("錯誤:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
