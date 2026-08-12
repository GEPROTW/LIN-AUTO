/* ocmd.c — dump 角色身上的「攻擊命令物件」(player+0x88)
 * 你攻擊時, 遊戲把攻擊命令掛在 [player+0x88]。這支在它出現時 dump 其內容,
 * 揭露攻擊命令的 vtable/opcode/目標/座標, 供之後重現攻擊。
 * gcc -shared -O2 -s -o ocmd.dll ocmd.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#define PLAYER 0x00C2D2B8u
#define ACT 0x88
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\ocmd.log"
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
static int RI(uintptr_t a){return rd(a,4)?*(int32_t*)a:0;}
static void dump_cmd(uint32_t c){
 L("  ┌ 命令物件 0x%08X: vtable=0x%08X opcode(+0x18)=0x%X",c,RU(c),RU(c+0x18)&0xFFFF);
 for(int o=0;o<0x80;o+=0x10){
  L("  │ +0x%02X: %08X %08X %08X %08X",o,RU(c+o),RU(c+o+4),RU(c+o+8),RU(c+o+0xC));
 }
 /* target 常在 +0x70(this[0x1c]); 若是實體指標, 印其座標 */
 uint32_t tg=RU(c+0x70);
 if(tg>=0x400000&&tg<0x7F000000&&rd(tg,0x40))
  L("  └ +0x70 目標? 0x%08X @(%d,%d)",tg,RI(tg+0x34),RI(tg+0x38));
}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");
 L("==== ocmd 攻擊命令側錄啟動 pid=%lu ====",GetCurrentProcessId());
 uint32_t last=0;
 for(;;){Sleep(60);
  uint32_t pl=RU(PLAYER);if(!pl)continue;
  uint32_t act=RU(pl+ACT);
  if(act&&act!=last&&rd(act,0x80)){
   L("[攻擊動作出現] player+0x88 = 0x%08X",act);
   dump_cmd(act);
   last=act;
  }
  if(!act)last=0;
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}
