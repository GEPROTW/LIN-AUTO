/* ohookcmd.c — hook 命令送出方法 FUN_004C8F30, 命令 opcode(+0x18)==0x3C33 時 dump 完整命令(0x1C0)
 * 比對「你真實攻擊」vs「我送的攻擊」命令內容, 找出傷害欄位。
 * FN 未被其他 hook 佔用, 可直接注入現有遊戲。 gcc -shared -O2 -s -o ohookcmd.dll ohookcmd.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define FN 0x004C8F30u
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\ohookcmd.log"
static FILE *g;
static void L(const char*f,...){if(!g)return;SYSTEMTIME t;GetLocalTime(&t);
 fprintf(g,"%02d:%02d:%02d.%03d  ",t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
 va_list a;va_start(a,f);vfprintf(g,f,a);va_end(a);fputc('\n',g);fflush(g);}
static volatile uint32_t g_cmd[0x70];   /* 0x1C0/4 */
static volatile uint32_t g_cnt=0;
static int heap(uint32_t v){return v>=0x00400000u&&v<0x7F000000u;}
void __attribute__((cdecl)) hp(uint32_t *pf){
 uint32_t cmd=pf[7];   /* ecx=this */
 if(heap(cmd)){
  uint16_t op=*(uint16_t*)(cmd+0x18);
  if(op==0x3C33){ memcpy((void*)g_cmd,(void*)cmd,0x1C0); g_cnt++; }
 }
}
static uint8_t *g_stub;
static int install(void){
 uint8_t *fn=(uint8_t*)FN;
 g_stub=(uint8_t*)VirtualAlloc(NULL,128,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
 if(!g_stub)return 0;uint8_t*s=g_stub;int i=0;
 s[i++]=0x60;s[i++]=0x9C;s[i++]=0x54;
 s[i++]=0xE8;*(int32_t*)(s+i)=(int32_t)(uintptr_t)hp-(int32_t)((uintptr_t)s+i+4);i+=4;
 s[i++]=0x83;s[i++]=0xC4;s[i++]=0x04;
 s[i++]=0x9D;s[i++]=0x61;
 s[i++]=0x55;s[i++]=0x8B;s[i++]=0xEC;s[i++]=0x6A;s[i++]=0xFF;
 s[i++]=0xE9;*(int32_t*)(s+i)=(int32_t)(FN+5)-(int32_t)((uintptr_t)s+i+4);i+=4;
 DWORD old;if(!VirtualProtect(fn,5,PAGE_EXECUTE_READWRITE,&old))return 0;
 fn[0]=0xE9;*(int32_t*)(fn+1)=(int32_t)(uintptr_t)g_stub-(int32_t)(FN+5);
 VirtualProtect(fn,5,old,&old);FlushInstructionCache(GetCurrentProcess(),fn,5);return 1;}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");
 L("==== ohookcmd 啟動 pid=%lu ====",GetCurrentProcessId());
 if(!install()){L("hook失敗");return 0;}
 L("hook OK(FUN_004C8F30). 攻擊時 dump 0x3C33 命令內容…");
 uint32_t last=0;
 for(;;){Sleep(50);
  if(g_cnt!=last){last=g_cnt;
   L("---- 0x3C33 命令 dump (this 0x1C0) ----");
   for(int o=0;o<0x1C0;o+=0x20){
    char line[256];int n=0;
    for(int k=0;k<8;k++) n+=snprintf(line+n,sizeof(line)-n,"%08X ",g_cmd[o/4+k]);
    L("  +0x%03X: %s",o,line);
   }
  }
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}
