/* orec.c — 攻擊側錄 DLL (32-bit)
 * 你手動打怪, 這支 DLL 側錄:
 *  (1) 列舉去重後的怪物(+0x10!=0)
 *  (2) 掃模組全域區[0xC00000,0xF0B000) 找「某隻怪的指標」出現在哪個全域
 *      → 平常無; 你鎖定攻擊時, 被打的怪會出現在某全域 = 當前目標全域/攻擊入口
 *  (3) 側錄角色狀態欄位變化
 * gcc -shared -O2 -s -o orec.dll orec.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define PLAYER_PTR_ADDR 0x00C2D2B8u
#define OFF_X 0x34
#define OFF_Y 0x38
#define OFF_AI 0x10
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\orec2.log"
#define MODLO 0x00400000u
#define MODHI 0x00F0B000u
#define GLO_LO 0x00400000u   /* 只掃 .data 全域段(較快, 目標全域在此) */
#define GLO_HI 0x00F0B000u

static FILE *g_log;
static void L(const char *fmt, ...) {
    if (!g_log) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(g_log, "%02d:%02d:%02d.%03d  ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap; va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
    fputc('\n', g_log); fflush(g_log);
}
static int readable(uintptr_t a, size_t n) {
    MEMORY_BASIC_INFORMATION m;
    if (!a || VirtualQuery((LPCVOID)a, &m, sizeof(m)) == 0) return 0;
    if (m.State != MEM_COMMIT || (m.Protect & PAGE_GUARD)) return 0;
    DWORD p = m.Protect & 0xFF;
    if (!(p==PAGE_READONLY||p==PAGE_READWRITE||p==PAGE_WRITECOPY||
          p==PAGE_EXECUTE_READ||p==PAGE_EXECUTE_READWRITE||p==PAGE_EXECUTE_WRITECOPY)) return 0;
    return a + n <= (uintptr_t)m.BaseAddress + m.RegionSize;
}
static uint32_t RU32(uintptr_t a){ return readable(a,4)?*(uint32_t*)a:0; }
static int32_t  RI32(uintptr_t a){ return readable(a,4)?*(int32_t*)a:0; }
static int is_heap(uint32_t v){ return v>=0x00400000u && v<0x7F000000u; }
static int looks_ent(uint32_t v){
    if(!is_heap(v)||!readable(v,0x40)) return 0;
    uint32_t vt=*(uint32_t*)v; if(vt<MODLO||vt>=MODHI) return 0;
    int x=RI32(v+OFF_X),y=RI32(v+OFF_Y);
    return x>0x2000&&x<0xF000&&y>0x2000&&y<0xF000;
}
static uint32_t g_base=0; static int g_len=0;
static int find_arr(uint32_t player){
    if(g_base && readable(g_base,g_len*4))
        for(int i=0;i<g_len;i++) if(RU32(g_base+i*4)==player) return 1;
    int bl=0; uint32_t bb=0; MEMORY_BASIC_INFORMATION m; uintptr_t a=0x10000;
    while(a<0x7F000000){
        if(VirtualQuery((LPCVOID)a,&m,sizeof(m))==0) break;
        uintptr_t b=(uintptr_t)m.BaseAddress,s=m.RegionSize; DWORD pr=m.Protect&0xFF;
        int ok=m.State==MEM_COMMIT&&!(m.Protect&PAGE_GUARD)&&
               (pr==PAGE_READWRITE||pr==PAGE_WRITECOPY||pr==PAGE_EXECUTE_READWRITE||pr==PAGE_EXECUTE_WRITECOPY);
        if(ok&&s<=0x4000000){
            for(uintptr_t p=b;p+4<=b+s;p+=4){
                if(*(uint32_t*)p!=player) continue;
                uintptr_t ss=p,ee=p+4;
                while(ss-4>=b&&looks_ent(*(uint32_t*)(ss-4))) ss-=4;
                while(ee+4<=b+s&&looks_ent(*(uint32_t*)ee)) ee+=4;
                int n=(int)((ee-ss)/4); if(n>bl){bl=n;bb=(uint32_t)ss;}
            }
        }
        a=b+s;
    }
    if(bl>=3){g_base=bb;g_len=bl;return 1;} return 0;
}
/* 掃模組全域區找 val, 回報最多 maxh 個位址 */
static int scan_global(uint32_t val, uint32_t *out, int maxh){
    int c=0; MEMORY_BASIC_INFORMATION m; uintptr_t a=GLO_LO;
    while(a<GLO_HI){
        if(VirtualQuery((LPCVOID)a,&m,sizeof(m))==0) break;
        uintptr_t b=(uintptr_t)m.BaseAddress,s=m.RegionSize; DWORD pr=m.Protect&0xFF;
        int ok=m.State==MEM_COMMIT&&!(m.Protect&PAGE_GUARD)&&
               (pr==PAGE_READWRITE||pr==PAGE_WRITECOPY||pr==PAGE_READONLY||pr==PAGE_EXECUTE_READ||pr==PAGE_EXECUTE_READWRITE);
        if(ok){
            uintptr_t e=b+s; if(e>GLO_HI) e=GLO_HI;
            for(uintptr_t p=(b<GLO_LO?GLO_LO:b);p+4<=e;p+=4)
                if(*(uint32_t*)p==val){ if(c<maxh) out[c]=(uint32_t)p; c++; }
        }
        a=b+s;
    }
    return c;
}
static DWORD WINAPI worker(LPVOID _){
    (void)_; g_log=fopen(LOGPATH,"a");
    L("==== orec 側錄啟動 pid=%lu ====", GetCurrentProcessId());
    uint32_t seen_target=0;
    for(;;){
        Sleep(400);
        uint32_t player=RU32(PLAYER_PTR_ADDR);
        if(!player){ continue; }
        if(!find_arr(player)) continue;
        int px=RI32(player+OFF_X),py=RI32(player+OFF_Y);
        /* 去重掃描每隻怪, 找其指標是否出現在全域 */
        uint32_t done[64]; int nd=0;
        for(int i=0;i<g_len;i++){
            uint32_t e=RU32(g_base+i*4);
            if(!is_heap(e)||e==player) continue;
            if(RU32(e+OFF_AI)==0) continue;       /* 只看怪(有AI指標) */
            int dup=0; for(int k=0;k<nd;k++) if(done[k]==e){dup=1;break;}
            if(dup) continue; if(nd<64) done[nd++]=e;
            uint32_t hits[8]; int c=scan_global(e,hits,8);
            if(c>0){
                char hb[128]; hb[0]=0; int off=0;
                for(int k=0;k<c&&k<8;k++) off+=snprintf(hb+off,sizeof(hb)-off,"0x%08X ",hits[k]);
                L("★怪 0x%08X @(%d,%d) 距%d 被全域引用(%d處): %s",
                  e,RI32(e+OFF_X),RI32(e+OFF_Y),abs(RI32(e+OFF_X)-px)+abs(RI32(e+OFF_Y)-py),c,hb);
                if(e!=seen_target){ seen_target=e;
                    L("   → 疑似『當前目標』= 0x%08X (若這是你剛點的怪, 上面全域位址就是目標入口)",e); }
            }
        }
    }
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;
    if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,worker,0,0,0);}
    return TRUE;
}

