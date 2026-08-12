# -*- coding: utf-8 -*-
r"""findcode.py — 枚舉活行程所有記憶體區段，找出「真正解壓後的程式碼/資料」所在。
需要 membridge 服務在跑。用法: python findcode.py [TWClient]
"""
import sys
import os
import math

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import membridge

TARGET = sys.argv[1] if len(sys.argv) > 1 else "TWClient"
KNOWN = [b"virtSurf", b"Access Violation", b"Sprite Ref", b"Client Version",
         b"ws2_32", b"ddraw", b"DDERR", b"%d,%d", b".xml", b"lineage", b"Socket",
         b"user32", b"gdi32", b"WindowMode"]


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


def prot_str(p):
    p &= 0xFF
    ex = p in (0x10, 0x20, 0x40, 0x80)
    wr = p in (0x04, 0x08, 0x40, 0x80)
    return ("X" if ex else "-") + ("W" if wr else "-")


def main():
    membridge.call("attach", target=TARGET, timeout=15)
    r = membridge.call("regions", target=TARGET, timeout=30)
    regs = r["regions"]
    regs.sort(key=lambda x: -x["size"])
    print("總可讀區段 %d 個, 合計 %.1f MB" % (r["count"], r["total"] / 1048576))
    print("%-12s %-11s %-4s %-6s %-5s %-6s %s" %
          ("base", "size", "prot", "type", "ent", "code?", "known-strings"))
    for reg in regs[:30]:
        base, size, prot, typ = reg["base"], reg["size"], reg["protect"], reg["type"]
        smp = min(0x10000, size)
        rb = membridge.call("read_bytes", target=TARGET, addr=base, size=smp, timeout=20)
        b = bytes.fromhex(rb["hex"]) if rb.get("hex") else b""
        ent = entropy(b)
        # 也取中段取樣搜字串
        hits = set(k.decode("latin1") for k in KNOWN if k in b)
        if size > 0x40000:
            mid = membridge.call("read_bytes", target=TARGET,
                                 addr=base + size // 2, size=0x10000, timeout=20)
            mb = bytes.fromhex(mid["hex"]) if mid.get("hex") else b""
            hits |= set(k.decode("latin1") for k in KNOWN if k in mb)
        typ_s = {0x1000000: "IMG", 0x40000: "MAP", 0x20000: "PRV"}.get(typ, hex(typ))
        # x86 碼特徵: 低熵(4.5~6.8) + 可執行
        codeish = "YES" if (prot_str(prot)[0] == "X" and 4.0 < ent < 6.9) else ""
        print("0x%010X 0x%09X %-4s %-6s %5.2f %-6s %s" %
              (base, size, prot_str(prot), typ_s, ent, codeish,
               ",".join(sorted(hits)) if hits else ""))


if __name__ == "__main__":
    main()
