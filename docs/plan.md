# 天堂 182「永念」私服 — 自動尋怪攻擊輔助 開發計畫

> 目標：把現有「純畫面辨識」的自動練功，升級成「**讀遊戲記憶體取得真實資料**」的穩健版。
> 前提：使用者自營私服 + 自控客戶端（`D:\永念182天堂`）。手法自由。
> 建立：2026-08-11

---

## 0. 現況盤點

| 項目 | 現況 |
|------|------|
| 目標客戶端 | `TWClient.bin` = `YongNian182TianParadise.bin`（MD5 `A7705F...`），x86 32-bit，ImageBase 0x400000 |
| **加殼** | **自製壓縮/加密殼**（單一 call/pop 自解密 stub，EP 在 `qiutvbml` 節 RVA 0xB0A000）。主碼區 entropy 7.98=壓縮。**非商用 VM 殼**（無 Themida/VMProtect/Oreans VM 簽章）→ 可用「跑到 OEP→dump→重建 IAT」脫殼。 |
| 反作弊 | 目錄含 GameGuard(`npk*`,`NP*`) 與 Oreans(`Xprotector.sys`) 檔，但同資料夾內 LiTo/LinHelperZ 等讀記憶體外掛能運作 → **私服的反作弊實際未擋注入/讀記憶體**。 |
| 既有自動化 | `自動練功輔助/auto_train.py`：純外部，SendInput+GetPixel，畫面辨識找怪（怪色/牆色/LOS），完整 GUI。**要保留其 GUI/操作骨架，替換偵測核心。** |
| 既有第三方外掛 | `LiTo`（畫面覆蓋輔助）、`LinHelperZ`/順刀（順刀外掛）。可當 offset 驗證的旁證。 |

---

## 1. 目標架構（v1，先驗證再擴充）

**偵測走記憶體、動作先沿用輸入模擬**（風險最低、直接升級現有 bot）：

```
┌─────────────────────────────────────────────┐
│  front-end (Python, 沿用 auto_train GUI)      │
│    ├─ memreader: 附加 TWClient 行程          │
│    │    讀 角色座標/HP/MP、怪物實體清單        │
│    ├─ hunt 決策: 選最近的敵對怪                │
│    └─ 動作: 目標世界座標→螢幕座標→點擊/攻擊鍵  │
└─────────────────────────────────────────────┘
                    │ ReadProcessMemory
                    ▼
             TWClient.bin (遊戲行程)
```

- 若 RE 後發現「世界座標→螢幕座標」投影太麻煩，或想更穩 → 升級 v2：注入 DLL 直接呼叫遊戲原生「設定目標/攻擊/移動」函數（免投影）。**此決策待 RE 結果**（使用者指定「先逆向再決定」）。

---

## 2. 逆向工作法（靜態 Ghidra ＋ 動態記憶體 雙軌）

1. **脫殼取得可分析映像**：啟動客戶端登入→行程到 OEP→`memtool.py dump` 把 image 區段落地→（必要時重建 IAT）→匯入 Ghidra 做真正分析。
2. **動態找結構（主力、最快）**：`memtool.py` 的 value-scanner（Cheat Engine 式）
   - 移動角色 → 掃「變動的座標值」→ 回溯持有座標的結構指標 = **角色物件**。
   - HP 條變動 → 掃 HP 值 → 定位 HP/MP/MaxHP 欄位。
   - 從角色物件鄰域/全域指標找 **實體清單**（怪物陣列或鏈結串列）：逐一取 id/座標/HP/type/陣營。
3. **靜態佐證（Ghidra）**：對脫殼映像用字串交叉引用（`move`/`attack`/`target`/`HP` 等）定位讀寫這些欄位的函數，反推結構 offset 與（v2 用的）原生函數位址。
4. 兩軌互相驗證，寫進 `docs/offsets.md` 清冊（標註「動態驗證 / 靜態推論」）。

---

## 3. 分階段路線圖

### P0 — 基礎建設
- [x] 確認目標身分、加殼型態、反作弊實況、Python/Ghidra 環境
- [x] 建專案骨架 `LIN-AUTO/{docs,tools,ghidra_proj,dumps}`
- [x] `tools/memtool.py`：附加行程 / 模組枚舉 / 區段走訪 / 讀寫 / AOB / value-scanner / dump（已用 notepad 端到端驗證）
- [x] Ghidra 匯入 `TWClient.bin` → 專案 `ghidra_proj/linproj`（管線建立；packed 檔分析價值低，真正分析 dump）

> ⚠ 客戶端由 `Login.exe` 以**系統管理員**啟動 → memtool 也要在**管理員 PowerShell** 執行才能開控制代碼。

### P1 — 記憶體地圖（逆向重心）
- [ ] 脫殼 dump（需客戶端執行中）
- [ ] 角色物件：座標(x,y)、HP/MP/MaxHP、地圖 id、朝向、狀態
- [ ] 實體清單：附近怪物/NPC/玩家 → id/座標/HP/type/陣營/存活旗標
- [ ] 世界→螢幕投影（供輸入模擬點怪）或 v2 原生目標函數
- [ ] 寫 `docs/offsets.md`

### P2 — 記憶體版自動尋怪
- [ ] `memreader` 模組：穩定讀出「玩家 + 怪物清單」
- [ ] hunt 決策：距離/陣營/HP 過濾、最近優先、視線
- [ ] 動作串接（點擊/攻擊鍵 或 v2 原生呼叫）
- [ ] 與現有 GUI 整合（新增「記憶體模式」開關，保留舊像素模式當備援）

### P3 — 輔助功能完善
- [ ] 自動補血/補魔（讀真實 HP/MP，取代像素條）
- [ ] 自動撿物 / buff 維持 / 定點巡邏 / 回城補給
- [ ] 多開支援（每-PID 附加）

---

## 4. 立即下一步

1. **使用者**：啟動 `D:\永念182天堂` 客戶端、登入並讓角色**進場站在有怪的地圖**。
2. `memtool.py attach TWClient` 確認可讀；`dump` 落地脫殼映像給 Ghidra。
3. value-scan 定位角色座標 → 這是所有功能的地基。

---

## 附：關鍵路徑
- 客戶端安裝：`D:\永念182天堂`
- 主程式：`D:\永念182天堂\TWClient.bin`（啟動器 `Login.exe`）
- Ghidra：`C:\Users\pc\orca\tools\ghidra\ghidra_12.1.2_PUBLIC`（JDK `...\jdk\jdk-21.0.12+8`）
- 本專案：`C:\Users\pc\orca\LIN-AUTO`
