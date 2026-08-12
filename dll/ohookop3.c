/* ohookop3.c — 完整側錄「轉向+攻擊」序列 (opcode 0x3C28..0x3C33) 的 this+8參數
 * 安全 detour(pushad). 需乾淨未 hook 的 FUN_004C7D80 → 重開遊戲後注入。
 * gcc -shared -O2 -s -o ohookop3.dll ohookop3.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#define FN 0x004C7D80u
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\ohookop3.log"
#define LO 0x3C28
#define HI 0x3C33
static FILE *g;
static void L(const char*f,...){if(!g)return;SYSTEMTIME t;GetLocalTime(&t);
 fprintf(g,"%02d:%02d:%02d.%03d  ",t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
 va_list a;va_start(a,f);vfprintf(g,f,a);va_end(a);fputc('\n',g);fflush(g);}
static volatile uint32_t g_full[32][10];   /* [op,this,a1..a8] */
static volatile uint32_t g_fcnt=0;
void __attribute__((cdecl)) hp_handler(uint32_t *pf){
 uint32_t op=pf[11];
 if(op>=LO && op<=HI){
  uint32_t i=g_fcnt & 31;
  g_full[i][0]=op; g_full[i][1]=pf[7];         /* this */
  for(int k=0;k<8;k++) g_full[i][2+k]=pf[10+k]; /* a1..a8 */
  g_fcnt++;
 }
}
static uint8_t *g_stub;
static int install(void){
 uint8_t *fn=(uint8_t*)FN;
 g_stub=(uint8_t*)VirtualAlloc(NULL,128,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
 if(!g_stub)return 0;uint8_t*s=g_stub;int i=0;
 s[i++]=0x60;s[i++]=0x9C;s[i++]=0x54;                     /* pushad;pushfd;push esp */
 s[i++]=0xE8;*(int32_t*)(s+i)=(int32_t)(uintptr_t)hp_handler-(int32_t)((uintptr_t)s+i+4);i+=4;
 s[i++]=0x83;s[i++]=0xC4;s[i++]=0x04;                     /* add esp,4 */
 s[i++]=0x9D;s[i++]=0x61;                                 /* popfd;popad */
 s[i++]=0x55;s[i++]=0x8B;s[i++]=0xEC;s[i++]=0x6A;s[i++]=0xFF; /* 原prologue */
 s[i++]=0xE9;*(int32_t*)(s+i)=(int32_t)(FN+5)-(int32_t)((uintptr_t)s+i+4);i+=4;
 DWORD old;if(!VirtualProtect(fn,5,PAGE_EXECUTE_READWRITE,&old))return 0;
 fn[0]=0xE9;*(int32_t*)(fn+1)=(int32_t)(uintptr_t)g_stub-(int32_t)(FN+5);
 VirtualProtect(fn,5,old,&old);FlushInstructionCache(GetCurrentProcess(),fn,5);return 1;}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");
 L("==== ohookop3 完整側錄啟動 pid=%lu ====",GetCurrentProcessId());
 if(!install()){L("hook安裝失敗");return 0;}
 L("hook OK. 站著只攻擊一次(轉向+攻擊), 側錄完整參數…");
 uint32_t last=0;
 for(;;){Sleep(50);uint32_t c=g_fcnt;
  while(last<c){uint32_t i=last&31;
   L("op=0x%X this=0x%08X | a1=0x%X a2=0x%X a3=0x%X a4=0x%X a5=0x%X(%d) a6=0x%X(%d) a7=0x%X a8=0x%X",
     g_full[i][0],g_full[i][1],g_full[i][2],g_full[i][3],g_full[i][4],g_full[i][5],
     g_full[i][6],(int)g_full[i][6],g_full[i][7],(int)g_full[i][7],g_full[i][8],g_full[i][9]);
   last++;}
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}
