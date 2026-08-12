# LIN-AUTO

天堂（Lineage）182 私服「永念」自架伺服器的**妖精弓手自動打怪內掛**（自用、自架伺服器 + 自有客戶端）。

以**遊戲內注入 DLL** 的方式，在行程內讀寫記憶體並呼叫遊戲原生攻擊路徑，避開外部 handle 觸發的反作弊崩潰。自動補血/補魔由既有的 LinHelperZ 負責，本專案**只做自動打怪**。

## 目錄

- `dll/` — 打怪 DLL 原始碼（`onatkN.c` 逐版迭代，最新為 `onatk26.c`）與注入器 `inject.c`。
  以 MinGW-w64 i686 編譯：`gcc -shared -O2 -s -o onatkN.dll onatkN.c`
- `tools/` — 記憶體工具：`memtool.py`（唯讀記憶體庫）、`watchdump3.py`（等待客戶端脫殼後擷取快照）等。
- `ghidra_scripts/` — Ghidra headless 逆向腳本（`DecompAt.java`、`Xrefs.java` 等）。
- `docs/` — `offsets.md`（位址/偏移登錄表）、`plan.md`。

## 已解決的核心技術

- **脫殼**：TWClient 自訂壓縮殼，開機約 10 秒後才在原地解密真實碼。
- **實體結構**：座標 `+0x34/+0x38`、objid `+0xC`、狀態 `+0x14`（`==8` 為死亡）、AI 指標 `+0x10`。
- **攻擊**：透過 WndProc 子類化在主執行緒呼叫遊戲原生 `FUN_0040e790`。
- **過濾器**：objid 大小辨別真怪 vs 寵物/玩家/NPC；反編譯地圖碰撞表做牆壁/視線(LOS)判斷；MINRANGE 防近戰崩潰。

> 註：記憶體傾印（`dumps/`）、Ghidra 專案（`ghidra_proj/`）、遊戲客戶端二進位（`TWClient.bin`）皆為專有或可重新產生的擷取物，已於 `.gitignore` 排除，不納入版控。
