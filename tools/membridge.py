# -*- coding: utf-8 -*-
r"""
membridge.py — 管理員↔非管理員 檔案橋接

架構:
  * 伺服端 (以系統管理員執行):  py membridge.py serve
      - 常駐，輪詢 dumps\mem_cmd.json，用 memtool 執行後把結果寫 dumps\mem_resp.json
  * 客戶端 (一般權限, 從我的工具鏈呼叫):
      py -c "import membridge,json; print(json.dumps(membridge.call('read', target='TWClient', addr=0x400000, type='u16', count=1), ensure_ascii=False))"

一次 UAC 授權後，所有記憶體操作都經由這個管道以管理員權限進行。
"""
import os
import sys
import json
import time
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
DUMPS = os.path.normpath(os.path.join(HERE, "..", "dumps"))
CMD = os.path.join(DUMPS, "mem_cmd.json")
RESP = os.path.join(DUMPS, "mem_resp.json")
SEQ = os.path.join(DUMPS, "mem_seq.txt")
LOG = os.path.join(DUMPS, "memserver.log")

sys.path.insert(0, HERE)


def _atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


# ============================ 客戶端 ============================
def call(op, timeout=120.0, **args):
    os.makedirs(DUMPS, exist_ok=True)
    # 取新 id
    nid = int(time.time() * 1000)
    req = {"id": nid, "op": op, "args": args}
    _atomic_write(CMD, json.dumps(req, ensure_ascii=False))
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with open(RESP, "r", encoding="utf-8") as f:
                resp = json.load(f)
            if resp.get("id") == nid:
                if resp.get("ok"):
                    return resp.get("result")
                raise RuntimeError("server error: %s" % resp.get("error"))
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        time.sleep(0.03)
    raise TimeoutError("等不到伺服端回應 (伺服端有在跑嗎? op=%s)" % op)


def server_alive():
    """回傳 (alive, info)。用 ping。"""
    try:
        r = call("ping", timeout=3.0)
        return True, r
    except Exception as e:
        return False, str(e)


# ============================ 伺服端 ============================
def serve():
    import ctypes
    import memtool
    admin = False
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass
    os.makedirs(DUMPS, exist_ok=True)

    def log(m):
        line = "%.3f %s\n" % (time.time(), m)
        try:
            with open(LOG, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass
        print(line, end="")

    log("memserver 啟動 admin=%s pid=%d" % (admin, os.getpid()))

    state = {"proc": None, "target": None}

    def get_proc(target=None):
        if target is not None:
            # (重新)附加
            if state["proc"]:
                try:
                    state["proc"].close()
                except Exception:
                    pass
            state["proc"] = memtool.Process.open(target)
            state["target"] = target
            return state["proc"]
        if state["proc"] is None:
            raise RuntimeError("尚未 attach")
        return state["proc"]

    def dispatch(op, a):
        if op == "ping":
            return {"admin": admin, "pid": os.getpid(),
                    "attached": state["target"]}
        if op == "ps":
            return _list_procs(a.get("filter"))
        if op == "attach":
            p = get_proc(a["target"])
            m = p.main_module()
            mods = [{"name": md["name"], "base": md["base"], "size": md["size"]}
                    for md in p.modules()[:60]]
            return {"pid": p.pid,
                    "main": {"name": m["name"], "base": m["base"], "size": m["size"]} if m else None,
                    "modules": mods}
        if op == "regions":
            p = get_proc(a.get("target"))
            regs = p.regions(image_only=a.get("image", False),
                             writable_only=a.get("writable", False))
            return {"count": len(regs),
                    "total": sum(r["size"] for r in regs),
                    "regions": regs[:400]}
        if op == "read":
            p = get_proc(a.get("target"))
            addr = a["addr"]
            t = a.get("type", "i32")
            cnt = a.get("count", 1)
            _, sz = memtool.TYPES[t]
            vals = []
            for i in range(cnt):
                vals.append(p.read_val(addr + i * sz, t))
            return {"addr": addr, "type": t, "values": vals}
        if op == "read_bytes":
            p = get_proc(a.get("target"))
            b = p.read(a["addr"], a["size"])
            return {"addr": a["addr"], "hex": (b.hex() if b else None)}
        if op == "scan":
            p = get_proc(a.get("target"))
            t = a.get("type", "i32")
            val = a["value"]
            hits = memtool.first_scan(p, t, val, align=a.get("step"),
                                      image_only=a.get("image", False),
                                      writable_only=not a.get("all_mem", False))
            pairs = [(h, val) for h in hits]
            memtool.save_state(t, pairs)
            return {"count": len(hits), "sample": [[h, val] for h in hits[:60]]}
        if op == "next":
            p = get_proc(a.get("target"))
            t, addrs = memtool.load_state()
            mode = a.get("mode", "value")
            val = a.get("value")
            res = memtool.next_scan(p, t, addrs, mode, val)
            memtool.save_state(t, res)
            return {"count": len(res), "sample": [[x, v] for x, v in res[:80]]}
        if op == "state":
            t, addrs = memtool.load_state()
            return {"type": t, "count": len(addrs),
                    "sample": [[x, v] for x, v in addrs[:80]]}
        if op == "aob":
            p = get_proc(a.get("target"))
            pat, mask = memtool.parse_pattern(a["pattern"])
            hits = []
            for base, size in memtool._iter_scan_regions(p, a.get("image", False), False):
                data = p.read(base, size)
                if not data:
                    continue
                for off in memtool.scan_bytes(data, pat, mask):
                    hits.append(base + off)
                    if len(hits) >= 300:
                        break
                if len(hits) >= 300:
                    break
            return {"count": len(hits), "hits": hits}
        if op == "poke":
            p = get_proc(a.get("target"))
            ok = p.write_val(a["addr"], a.get("type", "i32"), a["value"])
            return {"ok": ok}
        if op == "dump":
            p = get_proc(a.get("target"))
            m = p.module(a["module"]) if a.get("module") else p.main_module()
            if not m:
                raise RuntimeError("找不到模組")
            base, size = m["base"], m["size"]
            out = a.get("out") or os.path.join(DUMPS, "%s_%08X.dump" % (m["name"], base))
            written = 0
            pages_ok = 0
            pages_zero = 0
            with open(out, "wb") as f:
                off = 0
                CH = 0x100000
                while off < size:
                    n = min(CH, size - off)
                    b = p.read(base + off, n)
                    if b is None:
                        b = b"\x00" * n
                        pages_zero += 1
                    else:
                        if len(b) < n:
                            b = b + b"\x00" * (n - len(b))
                        pages_ok += 1
                    f.write(b)
                    written += n
                    off += n
            return {"out": out, "base": base, "size": size,
                    "written": written, "chunks_ok": pages_ok, "chunks_zero": pages_zero}
        raise RuntimeError("未知 op: %s" % op)

    last_id = None
    while True:
        try:
            with open(CMD, "r", encoding="utf-8") as f:
                req = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.03)
            continue
        if req.get("id") == last_id:
            time.sleep(0.02)
            continue
        last_id = req.get("id")
        op = req.get("op")
        a = req.get("args", {})
        try:
            result = dispatch(op, a)
            resp = {"id": last_id, "ok": True, "result": result}
        except Exception as e:
            resp = {"id": last_id, "ok": False, "error": "%s: %s" % (type(e).__name__, e)}
            log("op %s 失敗: %s" % (op, e))
        _atomic_write(RESP, json.dumps(resp, ensure_ascii=False))


def _list_procs(flt):
    import memtool
    import ctypes
    from ctypes import wintypes
    k32 = memtool.k32
    snap = k32.CreateToolhelp32Snapshot(memtool.TH32CS_SNAPPROCESS, 0)
    pe = memtool.PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(memtool.PROCESSENTRY32W)
    out = []
    ok = k32.Process32FirstW(snap, ctypes.byref(pe))
    while ok:
        name = pe.szExeFile
        if not flt or flt.lower() in name.lower():
            out.append({"pid": pe.th32ProcessID, "name": name})
        ok = k32.Process32NextW(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    return out


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        serve()
    else:
        # 命令列客戶端: membridge.py <op> key=val ...
        op = sys.argv[1]
        kw = {}
        for tok in sys.argv[2:]:
            k, _, v = tok.partition("=")
            try:
                v = int(v, 0)
            except ValueError:
                pass
            kw[k] = v
        print(json.dumps(call(op, **kw), ensure_ascii=False, indent=2))
