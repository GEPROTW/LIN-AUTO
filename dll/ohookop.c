/* ohookop.c — hook FUN_004C7D80 側錄每次送封包的 opcode (找真攻擊 opcode)
 * 你站著只攻擊時, 冒出來的 opcode 就是真攻擊請求。
 * 輕量 hook: stub 只讀 [esp+opcode] 存全域, 不讀緩衝(零錯誤風險)。
 * gcc -shared -O2 -s -o ohookop.dll ohookop.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#define FN 0x004C7D80u
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\ohookop.log"
static FILE *g;
static void L(const char*f,...){if(!g)return;SYSTEMTIME t;GetLocalTime(&t);
 fprintf(g,"%02d:%02d:%02d.%03d  ",t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
 va_list a;va_start(a,f);vfprintf(g,f,a);va_end(a);fputc('\n',g);fflush(g);}
/* 側錄環形緩衝 */
static volatile uint32_t g_ring[256];
static volatile uint32_t g_widx=0;   /* stub 遞增 */
/* stub 會用到的全域位址(絕對) */
static uint8_t *g_stub;
/* 安裝 hook */
static int install(void){
 uint8_t *fn=(uint8_t*)FN;
 g_stub=(uint8_t*)VirtualAlloc(NULL,128,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
 if(!g_stub)return 0;
 uint8_t *s=g_stub; int i=0;
 /* push eax */              s[i++]=0x50;
 /* push ecx (保留 this!) */ s[i++]=0x51;
 /* mov eax,[esp+0x10] */    s[i++]=0x8B;s[i++]=0x44;s[i++]=0x24;s[i++]=0x10;
 /* mov ecx,[g_widx] */      s[i++]=0x8B;s[i++]=0x0D;*(uint32_t*)(s+i)=(uint32_t)&g_widx;i+=4;
 /* and ecx,0xFF */          s[i++]=0x81;s[i++]=0xE1;*(uint32_t*)(s+i)=0xFF;i+=4;
 /* mov [g_ring+ecx*4],eax */s[i++]=0x89;s[i++]=0x04;s[i++]=0x8D;*(uint32_t*)(s+i)=(uint32_t)g_ring;i+=4;
 /* inc dword [g_widx] */    s[i++]=0xFF;s[i++]=0x05;*(uint32_t*)(s+i)=(uint32_t)&g_widx;i+=4;
 /* pop ecx */               s[i++]=0x59;
 /* pop eax */               s[i++]=0x58;
 /* 原始 prologue 5 bytes: 55 8B EC 6A FF */
 s[i++]=0x55;s[i++]=0x8B;s[i++]=0xEC;s[i++]=0x6A;s[i++]=0xFF;
 /* jmp back to FN+5 */      s[i++]=0xE9; *(int32_t*)(s+i)=(int32_t)(FN+5)-(int32_t)((uintptr_t)s+i+4); i+=4;
 /* 覆蓋 FN 前 5 bytes 為 jmp stub */
 DWORD old;
 if(!VirtualProtect(fn,5,PAGE_EXECUTE_READWRITE,&old))return 0;
 fn[0]=0xE9; *(int32_t*)(fn+1)=(int32_t)((uintptr_t)g_stub)-(int32_t)(FN+5);
 VirtualProtect(fn,5,old,&old);
 FlushInstructionCache(GetCurrentProcess(),fn,5);
 return 1;
}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");
 L("==== ohookop 啟動 pid=%lu ====",GetCurrentProcessId());
 if(!install()){L("hook 安裝失敗");return 0;}
 L("hook 已安裝於 FUN_004C7D80。請站著只攻擊, 側錄 opcode…");
 uint32_t ridx=0;
 for(;;){Sleep(50);
  uint32_t w=g_widx;
  while(ridx<w){uint32_t op=g_ring[ridx&0xFF];L("  send opcode = 0x%X (%u)",op,op);ridx++;}
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}
