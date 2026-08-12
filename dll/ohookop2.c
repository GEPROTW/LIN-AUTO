/* ohookop2.c — hook FUN_004C7D80, 抓 opcode 0x3C33(攻擊) 的完整參數
 * 安全 detour: stub=pushad/pushfd → 傳堆疊框給 C 處理常式 → 邏輯全在 C。
 * pushad+pushfd 後堆疊框 pf: pf[7]=ecx(this), pf[9]=ret, pf[10..17]=arg1..8, pf[11]=opcode(arg2)
 * gcc -shared -O2 -s -o ohookop2.dll ohookop2.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#define FN 0x004C7D80u
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\ohookop2.log"
#define ATK 0x3C33
static FILE *g;
static void L(const char*f,...){if(!g)return;SYSTEMTIME t;GetLocalTime(&t);
 fprintf(g,"%02d:%02d:%02d.%03d  ",t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
 va_list a;va_start(a,f);vfprintf(g,f,a);va_end(a);fputc('\n',g);fflush(g);}
static volatile uint32_t g_atk[16];
static volatile uint32_t g_atkcnt=0;
static volatile uint32_t g_ring[256];
static volatile uint32_t g_widx=0;
/* C 處理常式: pf=pushad框基址 */
void __attribute__((cdecl)) hp_handler(uint32_t *pf){
 uint32_t op=pf[11];              /* arg2 = opcode */
 g_ring[g_widx & 0xFF]=op; g_widx++;
 if(op==ATK){
  g_atk[0]=pf[7];                 /* this(ecx) */
  for(int k=0;k<8;k++) g_atk[1+k]=pf[10+k]; /* arg1..8 */
  g_atkcnt++;
 }
}
static uint8_t *g_stub;
static int install(void){
 uint8_t *fn=(uint8_t*)FN;
 g_stub=(uint8_t*)VirtualAlloc(NULL,128,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
 if(!g_stub)return 0;
 uint8_t*s=g_stub;int i=0;
 s[i++]=0x60;                     /* pushad */
 s[i++]=0x9C;                     /* pushfd */
 s[i++]=0x54;                     /* push esp (=pf) */
 s[i++]=0xE8; *(int32_t*)(s+i)=(int32_t)(uintptr_t)hp_handler-(int32_t)((uintptr_t)s+i+4); i+=4; /* call */
 s[i++]=0x83;s[i++]=0xC4;s[i++]=0x04; /* add esp,4 */
 s[i++]=0x9D;                     /* popfd */
 s[i++]=0x61;                     /* popad */
 s[i++]=0x55;s[i++]=0x8B;s[i++]=0xEC;s[i++]=0x6A;s[i++]=0xFF; /* 原prologue */
 s[i++]=0xE9; *(int32_t*)(s+i)=(int32_t)(FN+5)-(int32_t)((uintptr_t)s+i+4); i+=4; /* jmp back */
 DWORD old;
 if(!VirtualProtect(fn,5,PAGE_EXECUTE_READWRITE,&old))return 0;
 fn[0]=0xE9; *(int32_t*)(fn+1)=(int32_t)(uintptr_t)g_stub-(int32_t)(FN+5);
 VirtualProtect(fn,5,old,&old);
 FlushInstructionCache(GetCurrentProcess(),fn,5);
 return 1;
}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");
 L("==== ohookop2 啟動 pid=%lu ====",GetCurrentProcessId());
 if(!install()){L("hook 安裝失敗");return 0;}
 L("hook 已安裝。請站著只攻擊, 抓 0x3C33 完整參數…");
 uint32_t last=0;
 for(;;){Sleep(60);
  uint32_t c=g_atkcnt;
  if(c!=last){last=c;
   L("★攻擊 0x3C33 參數: this=0x%08X | a1=0x%X a2=0x%X a3=0x%X a4=0x%X a5=0x%X(%d) a6=0x%X(%d) a7=0x%X a8=0x%X",
     g_atk[0],g_atk[1],g_atk[2],g_atk[3],g_atk[4],g_atk[5],(int)g_atk[5],g_atk[6],(int)g_atk[6],g_atk[7],g_atk[8]);
  }
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}
