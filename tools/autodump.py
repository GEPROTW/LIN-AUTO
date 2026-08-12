# -*- coding: utf-8 -*-
r"""
autodump.py — 守株待兔：偵測到天堂客戶端出現就立刻 attach + dump 脫殼映像。
用於客戶端會定時閃退、只有短暫存活視窗的情況。
需要管理員 membridge 服務在跑 (py membridge.py serve)。
"""
import sys
import os
import time
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import membridge

TARGETS = ["twclient", "yongnian", "182tian", "182天"]
OUT = os.path.normpath(os.path.join(HERE, "..", "dumps", "TWClient_unpacked.dump"))
WAIT = 600  # 最多等 10 分鐘


def is_game(name):
    n = name.lower()
    if any(t in n for t in TARGETS):
        return True
    # 後備：以 .bin 結尾且非已知非遊戲檔
    if n.endswith(".bin") and n not in ("swap.bin",):
        return True
    return False


def main():
    ok, info = membridge.server_alive()
    if not ok:
        print("[X] 管理員記憶體服務沒回應，先啟動 membridge serve。", info)
        return
    print("[*] 服務就緒 admin=%s。等待天堂客戶端出現 (最多%ds)…" % (info.get("admin"), WAIT))
    t0 = time.time()
    last_names = set()
    while time.time() - t0 < WAIT:
        try:
            ps = membridge.call("ps", timeout=5)
        except Exception as e:
            print("[!] ps 失敗:", e)
            time.sleep(1)
            continue
        hit = next((p for p in ps if is_game(p["name"])), None)
        if hit:
            print("[+] 偵測到客戶端: pid=%d name=%s — 立刻 dump!" % (hit["pid"], hit["name"]))
            try:
                info2 = membridge.call("attach", target=hit["pid"], timeout=15)
                m = info2.get("main") or {}
                print("    attached base=0x%08X size=0x%X" %
                      (m.get("base", 0), m.get("size", 0)))
                r = membridge.call("dump", target=hit["pid"], out=OUT, timeout=120)
                print("[OK] dump 完成:")
                print("    ", json.dumps(r, ensure_ascii=False))
                print("    檔案:", OUT)
            except Exception as e:
                print("[X] attach/dump 失敗:", e)
            return
        # 顯示新出現的行程，方便除錯
        names = {p["name"] for p in ps}
        new = names - last_names
        interesting = [n for n in new if n.lower().endswith((".bin", ".exe"))
                       and any(k in n.lower() for k in ("lin", "tw", "yong", "login", "182"))]
        if interesting:
            print("    (新行程:", ", ".join(sorted(interesting)), ")")
        last_names = names
        time.sleep(0.12)
    print("[!] 等逾時，沒偵測到客戶端。")


if __name__ == "__main__":
    main()
