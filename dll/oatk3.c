/* oatk3.c — 真‧攻擊觸發 (32-bit)
 * 配方(來自 FUN_005ABC90 反組譯):
 *   cmd = op_new(0x1C0)                      ; 0x0079A150 __cdecl(size)
 *   FUN_004C7D80(ecx=cmd, 0,0x3C33,0,0,x,y,0,0)  ; __thiscall, callee 清堆疊
 *   (*(*(void**)cmd)[1])(ecx=cmd)            ; vtable+4 = 送出攻擊封包
 * 指令: oatk3_cmd.txt 寫 "atk" → 對最近的妖魔送攻擊(維持數秒)
 * gcc -shared -O2 -s -o oatk3.dll oatk3.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#define PLAYER 0x00C2D2B8u
#define TARGET 0x00C2D2B4u
#define OFF_X 0x34
#define OFF_Y 0x38
#define OFF_AI 0x10
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\oatk3.log"
#define CMDPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\oatk3_cmd.txt"
#define MODLO 0x00400000u
#define MODHI 0x00F0B000u
#define OP_NEW  0x0079A150u
#define FN_CTOR 0x004C7D80u
#define ATK_OPCODE 0x3C33
static FILE *g;
static void L(const char*f,...){if(!g)return;SYSTEMTIME t;GetLocalTime(&t);
 fprintf(g,"%02d:%02d:%02d.%03d  ",t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
 va_list a;va_start(a,f);vfprintf(g,f,a);va_end(a);fputc('\n',g);fflush(g);}
static int rdok(uintptr_t a,size_t n){MEMORY_BASIC_INFORMATION m;
 if(!a||VirtualQuery((LPCVOID)a,&m,sizeof(m))==0)return 0;
 if(m.State!=MEM_COMMIT||(m.Protect&PAGE_GUARD))return 0;DWORD p=m.Protect&0xFF;
 if(!(p==PAGE_READONLY||p==PAGE_READWRITE||p==PAGE_WRITECOPY||p==PAGE_EXECUTE_READ||p==PAGE_EXECUTE_READWRITE||p==PAGE_EXECUTE_WRITECOPY))return 0;
 return a+n<=(uintptr_t)m.BaseAddress+m.RegionSize;}
static uint32_t RU(uintptr_t a){return rdok(a,4)?*(uint32_t*)a:0;}
static int RI(uintptr_t a){return rdok(a,4)?*(int32_t*)a:0;}
static int heap(uint32_t v){return v>=0x400000u&&v<0x7F000000u;}
static int ent(uint32_t v){if(!heap(v)||!rdok(v,0x40))return 0;uint32_t t=*(uint32_t*)v;
 if(t<MODLO||t>=MODHI)return 0;int x=RI(v+OFF_X),y=RI(v+OFF_Y);
 return x>0x2000&&x<0xF000&&y>0x2000&&y<0xF000;}
static uint32_t gb=0;static int gl=0;
static int farr(uint32_t pl){if(gb&&rdok(gb,gl*4))for(int i=0;i<gl;i++)if(RU(gb+i*4)==pl)return 1;
 int bl=0;uint32_t bb=0;MEMORY_BASIC_INFORMATION m;uintptr_t a=0x10000;
 while(a<0x7F000000){if(VirtualQuery((LPCVOID)a,&m,sizeof(m))==0)break;
  uintptr_t b=(uintptr_t)m.BaseAddress,s=m.RegionSize;DWORD pr=m.Protect&0xFF;
  int ok=m.State==MEM_COMMIT&&!(m.Protect&PAGE_GUARD)&&(pr==PAGE_READWRITE||pr==PAGE_WRITECOPY||pr==PAGE_EXECUTE_READWRITE||pr==PAGE_EXECUTE_WRITECOPY);
  if(ok&&s<=0x4000000)for(uintptr_t p=b;p+4<=b+s;p+=4){if(*(uint32_t*)p!=pl)continue;
   uintptr_t ss=p,ee=p+4;while(ss-4>=b&&ent(*(uint32_t*)(ss-4)))ss-=4;while(ee+4<=b+s&&ent(*(uint32_t*)ee))ee+=4;
   int n=(int)((ee-ss)/4);if(n>bl){bl=n;bb=(uint32_t)ss;}}
  a=b+s;}
 if(bl>=3){gb=bb;gl=bl;return 1;}return 0;}
static uint32_t nearest(uint32_t pl,int px,int py){uint32_t best=0;long bd=1<<30;uint32_t seen[64];int ns=0;
 for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(RU(e+OFF_AI)==0)continue;
  int dup=0;for(int k=0;k<ns;k++)if(seen[k]==e){dup=1;break;}if(dup)continue;if(ns<64)seen[ns++]=e;
  long d=labs(RI(e+OFF_X)-px)+labs(RI(e+OFF_Y)-py);if(d<bd){bd=d;best=e;}}
 return best;}
/* op_new(size) __cdecl → EAX */
static void* op_new(unsigned size){void* r;
 __asm__ __volatile__("push %1\n\t call *%2\n\t add $4,%%esp\n\t"
  :"=a"(r):"r"(size),"r"(OP_NEW):"ecx","edx","memory");return r;}
/* FUN_004C7D80(ecx=cmd, 0,op,0,0,x,y,0,0) __thiscall(callee清堆疊) */
static void ctor_pkt(void* cmd,int op,int x,int y){void* r;
 __asm__ __volatile__(
  "push $0\n\t push $0\n\t"       /* a8,a7 */
  "push %[y]\n\t push %[x]\n\t"   /* y,x */
  "push $0\n\t push $0\n\t"       /* a4,a3 */
  "push %[op]\n\t push $0\n\t"    /* opcode, a1 */
  "mov %[c],%%ecx\n\t call *%[fn]\n\t"
  :"=a"(r):[y]"r"(y),[x]"r"(x),[op]"r"(op),[c]"r"(cmd),[fn]"r"(FN_CTOR):"ecx","edx","memory");}
/* 執行: (*(vtable[1]))(ecx=cmd) */
static void exec_cmd(void* cmd){void* vt=*(void**)cmd;void* fn=((void**)vt)[1];
 __asm__ __volatile__("mov %[c],%%ecx\n\t call *%[f]\n\t"
  ::[c]"r"(cmd),[f]"r"(fn):"eax","ecx","edx","memory");}
static void attack_entity(uint32_t e){
 int x=RI(e+OFF_X),y=RI(e+OFF_Y);
 if(rdok(TARGET,4))*(uint32_t*)TARGET=e;        /* 先設當前目標 */
 void* cmd=op_new(0x1C0);
 if(!cmd){L("op_new 失敗");return;}
 L("attack: new=0x%08X, 送 opcode 0x%X @(%d,%d) 對怪0x%08X",(uint32_t)cmd,ATK_OPCODE,x,y,e);
 ctor_pkt(cmd,ATK_OPCODE,x,y);
 exec_cmd(cmd);
 L("attack: 已送出");
}
static int ticks=0;
static void cmd(void){FILE*f=fopen(CMDPATH,"r");if(!f)return;char b[64]={0};fgets(b,64,f);fclose(f);remove(CMDPATH);
 if(strncmp(b,"atk",3)==0){ticks=12;L("[CMD] atk");}}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");L("==== oatk3 啟動 pid=%lu ====",GetCurrentProcessId());
 for(;;){Sleep(500);cmd();uint32_t pl=RU(PLAYER);if(!pl)continue;if(!farr(pl))continue;
  int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);
  if(ticks>0){ticks--;uint32_t m=nearest(pl,px,py);if(m)attack_entity(m);else L("找不到怪");}
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}

