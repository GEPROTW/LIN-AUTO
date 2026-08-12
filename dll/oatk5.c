/* oatk5.c — 真攻擊 (opcode 0x3C33 + 方向 a3)
 * 配方(側錄自真實攻擊): FUN_004C7D80(ecx=cmd, 0,0x3C33,dir,0, mx,my, 0,0); 執行=vtable+4
 *   dir = 玩家→怪 的 8 方向(0-7)。 gcc -shared -O2 -s -o oatk5.dll oatk5.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#define PLAYER 0x00C2D2B8u
#define TARGET 0x00C2D2B4u
#define OFF_X 0x34
#define OFF_Y 0x38
#define OFF_AI 0x10
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\oatk5.log"
#define CMDPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\oatk5_cmd.txt"
#define MODLO 0x00400000u
#define MODHI 0x00F0B000u
#define OP_NEW  0x0079A150u
#define FN_CTOR 0x004C7D80u
#define ATK 0x3C33
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
/* 8方向(L1J式): (dx,dy)->heading */
static int heading(int px,int py,int mx,int my){
 int dx=(mx>px)-(mx<px), dy=(my>py)-(my<py);
 if(dx==0&&dy<0)return 0; if(dx>0&&dy<0)return 1; if(dx>0&&dy==0)return 2; if(dx>0&&dy>0)return 3;
 if(dx==0&&dy>0)return 4; if(dx<0&&dy>0)return 5; if(dx<0&&dy==0)return 6; if(dx<0&&dy<0)return 7;
 return 0;}
/* 用呼叫慣例屬性的函數指標, 讓 GCC 產生正確呼叫碼 */
typedef void* (__attribute__((cdecl))    *newfn_t)(unsigned);
typedef void* (__attribute__((thiscall)) *ctorfn_t)(void*,int,int,int,int,int,int,int,int);
typedef void  (__attribute__((thiscall)) *execfn_t)(void*);
static void attack(uint32_t pl,int px,int py,uint32_t e){
 (void)pl;
 int mx=RI(e+OFF_X),my=RI(e+OFF_Y),dir=heading(px,py,mx,my);
 if(rdok(TARGET,4))*(uint32_t*)TARGET=e;
 newfn_t op_new=(newfn_t)OP_NEW;
 void* cmd=op_new(0x1C0); if(!cmd){L("op_new失敗");return;}
 L("attack: 怪0x%08X @(%d,%d) dir=%d",e,mx,my,dir);
 ctorfn_t ctor=(ctorfn_t)FN_CTOR;
 /* 第一步: 轉向目標 (opcode 0x3C28+dir), 帶玩家座標 */
 void* c0=op_new(0x1C0);
 if(c0){ ctor(c0, 0, 0x3C28+dir, 0, 0, px, py, 0, 0);
         void* v0=*(void**)c0; ((execfn_t)((void**)v0)[1])(c0); }
 /* 第二步: 攻擊 (opcode 0x3C33), 帶怪座標 */
 ctor(cmd, 0, ATK, dir, 0, mx, my, 0, 0);      /* this=cmd, a1..a8 */
 void* vt=*(void**)cmd; execfn_t ex=(execfn_t)((void**)vt)[1];
 ex(cmd);                                       /* vtable+4 送出 */
}
static int ticks=0;
static void cmd(void){FILE*f=fopen(CMDPATH,"r");if(!f)return;char b[64]={0};fgets(b,64,f);fclose(f);remove(CMDPATH);
 if(strncmp(b,"atk",3)==0){ticks=16;L("[CMD] atk");}}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");L("==== oatk5 啟動 pid=%lu ====",GetCurrentProcessId());
 for(;;){Sleep(400);cmd();uint32_t pl=RU(PLAYER);if(!pl)continue;if(!farr(pl))continue;
  int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);
  if(ticks>0){ticks--;uint32_t m=nearest(pl,px,py);if(m)attack(pl,px,py,m);else L("找不到怪");}
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}
