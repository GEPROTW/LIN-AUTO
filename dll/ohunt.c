/* ohunt.c — 天堂182「永念」自動尋怪 in-game DLL (32-bit)
 *
 * 階段1(本檔)：載入遊戲後，在行程內讀取角色、列舉附近實體(怪物)，寫 log 驗證。
 * 以檔案指令通道接收測試指令(供之後驗證攻擊函數)。
 *
 * 已知結構(來自逆向, base 0x400000 無 ASLR):
 *   角色物件指標   [0x00C2D2B8]
 *   實體物件: vtable +0x00, 物件ID +0x14(int), X +0x34(int), Y +0x38(int)
 *
 * 建置(MinGW i686): gcc -m32 -shared -O2 -s -o ohunt.dll ohunt.c -lpsapi
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define PLAYER_PTR_ADDR 0x00C2D2B8u
#define OFF_ID   0x14
#define OFF_X    0x34
#define OFF_Y    0x38
#define OFF_NAME 0x68

#define LOGPATH  "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\ohunt3.log"
#define CMDPATH  "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\ohunt_cmd.txt"
#define MODLO 0x00400000u
#define MODHI 0x00F0B000u

static FILE *g_log;

static void L(const char *fmt, ...) {
    if (!g_log) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(g_log, "%02d:%02d:%02d.%03d  ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap; va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}

/* ---- 安全讀取：先確認位址落在可讀已提交頁，避免存取違規 ---- */
static int readable(uintptr_t addr, size_t n) {
    MEMORY_BASIC_INFORMATION mbi;
    if (addr == 0) return 0;
    if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    DWORD p = mbi.Protect & 0xFF;
    if (p == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) return 0;
    if (!(p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
          p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY))
        return 0;
    /* 確認整段在同一區塊範圍內 */
    uintptr_t regend = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    return (addr + n) <= regend;
}
static uint32_t RU32(uintptr_t a) { return readable(a, 4) ? *(uint32_t*)a : 0; }
static int32_t  RI32(uintptr_t a) { return readable(a, 4) ? *(int32_t*)a : 0; }

static int is_heap(uint32_t v) { return v >= 0x00400000u && v < 0x7F000000u; }

/* 判斷某指標是否『像實體』：heap 指標 + vtable 落在模組碼區 + 座標合理 */
static int looks_like_entity(uint32_t v) {
    if (!is_heap(v) || !readable(v, 0x40)) return 0;
    uint32_t vt = *(uint32_t*)v;                     /* vtable */
    if (vt < MODLO || vt >= MODHI) return 0;
    int x = RI32(v + OFF_X), y = RI32(v + OFF_Y);
    if (x < 0x2000 || x > 0xF000 || y < 0x2000 || y > 0xF000) return 0;  /* ~8192..61440 */
    return 1;
}

/* ---- 在行程內找『含玩家指標且鄰居為實體』的陣列 ---- */
static uint32_t g_arr_base = 0;   /* 快取上次找到的陣列 */
static int      g_arr_len  = 0;
static int g_diag_regions = 0, g_diag_hits = 0;

static int find_entity_array(uint32_t player, int px, int py) {
    (void)px; (void)py;
    if (g_arr_base && readable(g_arr_base, g_arr_len * 4)) {
        for (int i = 0; i < g_arr_len; i++)
            if (RU32(g_arr_base + i*4) == player) return 1;
    }
    g_diag_regions = 0; g_diag_hits = 0;
    int bestlen = 0; uint32_t bestbase = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0x00010000;
    while (addr < 0x7F000000) {
        if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) break;
        uintptr_t base = (uintptr_t)mbi.BaseAddress, size = mbi.RegionSize;
        DWORD pr = mbi.Protect & 0xFF;
        int usable = (mbi.State == MEM_COMMIT) && !(mbi.Protect & PAGE_GUARD) &&
                     (pr == PAGE_READWRITE || pr == PAGE_WRITECOPY ||
                      pr == PAGE_EXECUTE_READWRITE || pr == PAGE_EXECUTE_WRITECOPY);
        if (usable && size <= 0x4000000) {
            g_diag_regions++;
            for (uintptr_t a = base; a + 4 <= base + size; a += 4) {
                if (*(uint32_t*)a != player) continue;
                g_diag_hits++;
                /* 往回/往前擴成陣列(鄰居=實體) */
                uintptr_t s = a, e = a + 4;
                while (s - 4 >= base && looks_like_entity(*(uint32_t*)(s - 4))) s -= 4;
                while (e + 4 <= base + size && looks_like_entity(*(uint32_t*)e)) e += 4;
                int n = (int)((e - s) / 4);
                if (n > bestlen) { bestlen = n; bestbase = (uint32_t)s; }
            }
        }
        addr = base + size;
    }
    if (bestlen >= 3) { g_arr_base = bestbase; g_arr_len = bestlen; return 1; }
    return 0;
}

/* ---- 讀取指令檔(供測試) ---- */
static void poll_cmd(void) {
    FILE *f = fopen(CMDPATH, "r");
    if (!f) return;
    char buf[256] = {0};
    if (fgets(buf, sizeof(buf), f)) {
        L("[CMD] 收到指令: %s", buf);
        /* 之後在此接候選攻擊函數呼叫做驗證 */
    }
    fclose(f);
    remove(CMDPATH);
}

static DWORD WINAPI worker(LPVOID p) {
    (void)p;
    g_log = fopen(LOGPATH, "a");
    L("==== ohunt DLL 載入, 執行緒啟動 pid=%lu ====", GetCurrentProcessId());
    int tick = 0;
    for (;;) {
        Sleep(1000);
        poll_cmd();
        uint32_t player = RU32(PLAYER_PTR_ADDR);
        if (!player) { if (tick++ % 10 == 0) L("尚未進場(角色指標=0)"); continue; }
        int px = RI32(player + OFF_X), py = RI32(player + OFF_Y);
        uint32_t pid = RU32(player + OFF_ID);
        if (!find_entity_array(player, px, py)) {
            L("角色@(%d,%d) id=%u  找不到實體陣列 (掃%d區/player命中%d)",
              px, py, pid, g_diag_regions, g_diag_hits);
            continue;
        }
        /* 每 5 秒詳細 dump 一次全部實體(含名稱), 以找出怪物判別欄位 */
        if (tick % 5 == 0) {
            L("---- 詳細 dump: 角色@(%d,%d) id=%u  陣列0x%08X len=%d ----",
              px, py, pid, g_arr_base, g_arr_len);
            for (int i = 0; i < g_arr_len; i++) {
                uint32_t e = RU32(g_arr_base + i*4);
                if (!is_heap(e)) { L("  [%d] 0x%08X 非法", i, e); continue; }
                char nm[48]; nm[0] = 0;
                uint32_t np = RU32(e + OFF_NAME);
                if (readable(np, 1)) {
                    for (int k = 0; k < 40; k++) {
                        if (!readable(np + k, 1)) break;
                        char c = *(char*)(np + k);
                        nm[k] = c; nm[k+1] = 0;
                        if (c == 0) break;
                    }
                }
                L("  [%d] ep=0x%08X vt=0x%08X (%d,%d) id=0x%X | +08=0x%X +0C=0x%X +10=0x%X +1C=0x%X +CD=%d | name='%s'",
                  i, e, RU32(e), RI32(e+OFF_X), RI32(e+OFF_Y), RU32(e+OFF_ID),
                  RU32(e+8), RU32(e+0xC), RU32(e+0x10), RU32(e+0x1C),
                  (int)(readable(e+0xCD,1)?*(unsigned char*)(e+0xCD):0),
                  (e==player)?"<自己>":nm);
            }
        }
        /* 最近的非自己實體 */
        int best = -1; long bestd = 0x7FFFFFFF; int cnt = 0;
        for (int i = 0; i < g_arr_len; i++) {
            uint32_t e = RU32(g_arr_base + i*4);
            if (!is_heap(e) || e == player) continue;
            int ex = RI32(e + OFF_X), ey = RI32(e + OFF_Y);
            long d = (long)abs(ex - px) + abs(ey - py);
            cnt++;
            if (d < bestd) { bestd = d; best = i; }
        }
        if (best >= 0) {
            uint32_t e = RU32(g_arr_base + best*4);
            L("角色@(%d,%d) 附近實體%d | 最近 @(%d,%d) 距%ld",
              px, py, cnt, RI32(e+OFF_X), RI32(e+OFF_Y), bestd);
        }
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, worker, NULL, 0, NULL);
    }
    return TRUE;
}

