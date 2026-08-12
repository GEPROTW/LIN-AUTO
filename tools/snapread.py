# -*- coding: utf-8 -*-
r"""snapread.py — 讀取 watchdump3 的區段快照(regions3), 像讀活記憶體一樣依位址取值。
用來離線探索活的角色/實體結構(零風險, 不碰遊戲)。
"""
import os
import struct
import sys

R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dumps", "regions3")
R = os.path.normpath(R)

_regions = []   # (base, size, path)
_cache = {}


def _load():
    man = os.path.join(R, "manifest.txt")
    for line in open(man, encoding="utf-8").read().splitlines()[1:]:
        f = line.split("\t")
        if len(f) < 2:
            continue
        base = int(f[0], 16)
        size = int(f[1], 16)
        p = os.path.join(R, "mem_%08X.bin" % base)
        if os.path.exists(p):
            _regions.append((base, size, p))
    _regions.sort()


def read(addr, n):
    for base, size, path in _regions:
        if base <= addr < base + size:
            b = _cache.get(path)
            if b is None:
                b = open(path, "rb").read()
                _cache[path] = b
            off = addr - base
            return b[off:off + n]
        if base > addr:
            break
    return None


def u32(a):
    b = read(a, 4)
    return struct.unpack("<I", b)[0] if b and len(b) >= 4 else None


def i32(a):
    b = read(a, 4)
    return struct.unpack("<i", b)[0] if b and len(b) >= 4 else None


def u16(a):
    b = read(a, 2)
    return struct.unpack("<H", b)[0] if b and len(b) >= 2 else None


def u8(a):
    b = read(a, 1)
    return b[0] if b else None


def is_code_ptr(v):
    return v is not None and 0x400000 <= v < 0xF0B000


def is_heap_ptr(v):
    return v is not None and 0x10000000 <= v < 0x7F000000


PLAYER = 0x33B997D8
PX, PY = 34120, 32798


def find_value(val):
    """全快照搜尋 dword==val, 回傳位址清單。"""
    needle = struct.pack("<I", val)
    hits = []
    for base, size, path in _regions:
        b = _cache.get(path)
        if b is None:
            b = open(path, "rb").read()
            _cache[path] = b
        idx = b.find(needle)
        while idx != -1:
            if idx % 4 == 0:
                hits.append(base + idx)
            idx = b.find(needle, idx + 1)
    return hits


def find_entity_manager():
    print("=== 追蹤『真怪物陣列』的穩定全域根 ===")
    PX, PY = 34120, 32798
    # 1) 找玩家在哪些 heap 陣列
    slots = [h for h in find_value(PLAYER) if not (0x400000 <= h < 0xF0B000)]
    print("玩家出現在 heap 陣列 slot:", [hex(h) for h in slots])
    for slot in slots:
        # 找陣列起點與長度(連續 heap 指標, 且指向的物件座標接近玩家)
        base = slot
        while True:
            v = u32(base - 4)
            if not is_heap_ptr(v):
                break
            x = i32(v + 0x34)
            if x is None or abs(x - PX) > 5000:
                break
            base -= 4
        end = slot
        while True:
            v = u32(end)
            if not is_heap_ptr(v):
                break
            x = i32(v + 0x34)
            if x is None or abs(x - PX) > 5000:
                break
            end += 4
        n = (end - base) // 4
        if n < 3:
            continue
        print("  陣列 base=0x%08X 長度=%d (玩家 idx=%d)" % (base, n, (slot - base) // 4))
        # 2) 誰指向這個 base? (vector 的 begin 指標)
        owners = find_value(base)
        for o in owners:
            loc = "全域固定" if 0x400000 <= o < 0xF0B000 else "heap"
            print("     <- 指向陣列的 0x%08X (%s)" % (o, loc))
            if loc == "heap":
                for probe in (o, o - 4, o - 8, o - 0xc):
                    for oo in find_value(probe):
                        if 0x400000 <= oo < 0xF0B000:
                            print("        <<- ★全域 0x%08X -> 物件(0x%08X) -> 陣列(0x%08X)"
                                  % (oo, probe, base))


def main():
    _load()
    print("regions:", len(_regions))
    find_entity_manager()
    return
    print("regions:", len(_regions))
    cntA = u32(0x00C2D2E0)
    print("實體清單A數量 =", cntA)
    print("\n=== 搜尋玩家指標 0x%08X 的所有出現位置 ===" % PLAYER)
    hits = find_value(PLAYER)
    for h in hits:
        # 看前後是否為 heap 指標陣列
        neigh = [u32(h + k * 4) for k in range(-2, 6)]
        nheap = sum(1 for v in neigh if is_heap_ptr(v))
        loc = "全域" if 0x400000 <= h < 0xF0B000 else "heap"
        print("  0x%08X (%s) 鄰近heap指標數=%d : %s"
              % (h, loc, nheap, " ".join("0x%08X" % (v or 0) for v in neigh)))
    # 挑鄰近多為 heap 指標的那個當陣列
    arr_slot = None
    for h in hits:
        if 0x400000 <= h < 0xF0B000:
            continue
        neigh = [u32(h + k * 4) for k in range(-3, 4)]
        if sum(1 for v in neigh if is_heap_ptr(v)) >= 5:
            arr_slot = h
            break
    if arr_slot:
        print("\n★實體陣列(玩家所在slot)= 0x%08X" % arr_slot)
        _dump_entities_from_slot(arr_slot)
        return
    print("(玩家不在陣列, 改法待議)")
    return


def _dump_entities_from_slot(player_slot):
    # 玩家在陣列中的哪個 index? 往回找陣列起點: 連續 heap 指標
    start = player_slot
    while is_heap_ptr(u32(start - 4)):
        start -= 4
    cntA = u32(0x00C2D2E0) or 80
    print("陣列起點 ~0x%08X, 玩家 index=%d" % (start, (player_slot - start) // 4))
    print("\n=== 前 24 實體: ep / vtable / (+34,+38) / (+0x10,+14) 各種座標候選 ===")
    for i in range(min(24, cntA + 2)):
        ep = u32(start + i * 4)
        if not is_heap_ptr(ep):
            print("  [%2d] 0x%08X 非heap" % (i, ep or 0))
            continue
        vt = u32(ep)
        vals = {o: i32(ep + o) for o in (0x10, 0x14, 0x34, 0x38, 0x3c, 0x40)}
        me = " <==玩家" if ep == PLAYER else ""
        print("  [%2d] ep=0x%08X vt=0x%08X | +34=%d +38=%d | +10=%d +14=%d%s"
              % (i, ep, vt or 0, vals[0x34] or 0, vals[0x38] or 0,
                 vals[0x10] or 0, vals[0x14] or 0, me))

    # 候選實體陣列指標
    candidates = [u32(0x00C2D2BC), u32(0x00C2D2E8)]
    print("候選陣列指標:", [hex(c) if c else None for c in candidates])

    arr = None
    # 驗證: 陣列前幾個元素應為 heap 指標, 指向 vtable 在 code 範圍的物件
    for c in candidates:
        if not is_heap_ptr(c):
            continue
        e0 = u32(c)
        if is_heap_ptr(e0) and is_code_ptr(u32(e0)):
            arr = c
            print("★確認實體陣列 @ 0x%08X (元素0 -> 0x%08X, vtable 0x%08X)"
                  % (c, e0, u32(e0)))
            break
    if arr is None:
        # 掃模組 .data 找陣列
        print("候選不成立, 掃描模組資料區找陣列…")
        for a in range(0x00C00000, 0x00F0B000, 4):
            c = u32(a)
            if is_heap_ptr(c):
                e0 = u32(c)
                if is_heap_ptr(e0) and is_code_ptr(u32(e0)):
                    e1 = u32(c + 4)
                    if is_heap_ptr(e1) and is_code_ptr(u32(e1)):
                        # 兩個都像實體, 檢查座標接近玩家
                        x0 = i32(e0 + 0x34)
                        y0 = i32(e0 + 0x38)
                        if x0 and abs(x0 - PX) < 2000 and abs(y0 - PY) < 2000:
                            arr = c
                            print("★掃到實體陣列 @ 0x%08X (由全域 0x%08X 指向)" % (c, a))
                            break
    if arr is None:
        print("找不到實體陣列")
        return

    print("\n=== 前 20 個實體 (ptr / vtable / X,Y / dist / +0x14 +0x18 +0x15 +0xCD) ===")
    for i in range(min(20, cntA or 20)):
        ep = u32(arr + i * 4)
        if not is_heap_ptr(ep):
            print("  [%2d] 0x%08X (非法)" % (i, ep or 0))
            continue
        vt = u32(ep)
        x = i32(ep + 0x34)
        y = i32(ep + 0x38)
        dist = abs((x or 0) - PX) + abs((y or 0) - PY) if x else -1
        f14 = u32(ep + 0x14)
        f18 = u32(ep + 0x18)
        b15 = u8(ep + 0x15)
        bcd = u8(ep + 0xCD)
        me = " <==玩家" if ep == PLAYER else ""
        print("  [%2d] ep=0x%08X vt=0x%08X (%d,%d) d=%d +14=%d +18=0x%X +15=%d +CD=%d%s"
              % (i, ep, vt or 0, x or 0, y or 0, dist, f14 or 0, f18 or 0, b15 or 0, bcd or 0, me))


if __name__ == "__main__":
    main()
