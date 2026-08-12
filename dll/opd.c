/* opd.c — 角色狀態差異側錄 (32-bit)
 * 側錄角色物件 [0xC2D2B8] 前 0x140 bytes 的變化 + 當前目標 [0xC2D2B4]。
 * 你「站著不動、只攻擊一隻怪」時, 變化的欄位就是攻擊狀態/動作/目標。
 * gcc -shared -O2 -s -o opd.dll opd.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#define PLAYER 0x00C2D2B8u
#define TARGET 0x00C2D2B4u
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\opd.log"
#define SPAN 0x140
static FILE *g;
static void L(const char*f,...){if(!g)return;SYSTEMTIME t;GetLocalTime(&t);
 fprintf(g,"%02d:%02d:%02d.%03d  ",t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
 va_list a;va_start(a,f);vfprintf(g,f,a);va_end(a);fputc('\n',g);fflush(g);}
static int rd(uintptr_t a,size_t n){MEMORY_BASIC_INFORMATION m;
 if(!a||VirtualQuery((LPCVOID)a,&m,sizeof(m))==0)return 0;
 if(m.State!=MEM_COMMIT||(m.Protect&PAGE_GUARD))return 0;DWORD p=m.Protect&0xFF;
 if(!(p==PAGE_READONLY||p==PAGE_READWRITE||p==PAGE_WRITECOPY||p==PAGE_EXECUTE_READ||p==PAGE_EXECUTE_READWRITE||p==PAGE_EXECUTE_WRITECOPY))return 0;
 return a+n<=(uintptr_t)m.BaseAddress+m.RegionSize;}
static uint32_t RU(uintptr_t a){return rd(a,4)?*(uint32_t*)a:0;}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");
 L("==== opd 角色差異側錄啟動 pid=%lu (站著不動只攻擊) ====",GetCurrentProcessId());
 uint32_t prev[SPAN/4]; int have=0; uint32_t ptgt=0; uint32_t pp=0;
 for(;;){Sleep(150);
  uint32_t pl=RU(PLAYER);
  uint32_t tg=RU(TARGET);
  if(tg!=ptgt){L("[目標] [0xC2D2B4]: 0x%08X -> 0x%08X",ptgt,tg);ptgt=tg;}
  if(!pl){have=0;continue;}
  if(pl!=pp){L("[角色指標變] 0x%08X",pl);pp=pl;have=0;}
  if(!rd(pl,SPAN)){continue;}
  uint32_t cur[SPAN/4];
  for(int i=0;i<SPAN/4;i++)cur[i]=RU(pl+i*4);
  if(have){
   for(int i=0;i<SPAN/4;i++){
    /* 跳過座標(+0x34,+0x38,+0x3C,+0x40,+0x44,+0x48)避免走位噪音 */
    int off=i*4; if(off>=0x34&&off<=0x48)continue;
    if(cur[i]!=prev[i]) L("  +0x%03X: 0x%08X -> 0x%08X",off,prev[i],cur[i]);
   }
  }
  for(int i=0;i<SPAN/4;i++)prev[i]=cur[i]; have=1;
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}
