/* onatk.c — 原生高階攻擊 (呼叫 FUN_0040e790 = 點怪「對物件動作」入口)
 * 反編譯確認: 真實攻擊 = FUN_0040e790(目標) → 依類型送 opcode 0x22(+目標物件ID) 攻擊 / 0x70 移動接近。
 * 在遊戲主執行緒(子類化 WndProc)呼叫, 讓遊戲用完整原生流程攻擊。
 * 指令檔 onatk_cmd.txt:  atk = 對最近怪 FUN_0040e790 ;  s22 = 直送 0x22 封包 ; find = 只列怪
 * gcc -shared -O2 -s -o onatk.dll onatk.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#define PLAYER 0x00C2D2B8u
#define TARGET 0x00C2D2B4u
#define HOVERSEL 0x00ABF440u   /* DAT_00abf440 點擊/懸停選取的目標候選 */
#define OFF_X 0x34
#define OFF_Y 0x38
#define OFF_ID 0x0C
#define OFF_AI 0x10
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\onatk.log"
#define CMDPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\onatk_cmd.txt"
#define MODLO 0x00400000u
#define MODHI 0x00F0B000u
#define FN_ACT  0x0040E790u    /* FUN_0040e790(int target)  __cdecl : 高階對物件動作(攻擊/接近) */
#define FN_SEND 0x00580E50u    /* FUN_00580e50(fmt, opcode, ...) __cdecl variadic : 送封包 */
#define FMT_022 0x008CAC24u    /* opcode 0x22 的封包格式字串位址 */
#define WM_ATK (WM_APP+7)
#define WM_S22 (WM_APP+8)
static FILE*g;
static void L(const char*f,...){if(!g)return;SYSTEMTIME t;GetLocalTime(&t);
 fprintf(g,"%02d:%02d:%02d.%03d  ",t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
 va_list a;va_start(a,f);vfprintf(g,f,a);va_end(a);fputc('\n',g);fflush(g);}
static int rdok(uintptr_t a,size_t n){MEMORY_BASIC_INFORMATION m;
 if(!a||VirtualQuery((LPCVOID)a,&m,sizeof(m))==0)return 0;if(m.State!=MEM_COMMIT||(m.Protect&PAGE_GUARD))return 0;
 DWORD p=m.Protect&0xFF;if(!(p==PAGE_READONLY||p==PAGE_READWRITE||p==PAGE_WRITECOPY||p==PAGE_EXECUTE_READ||p==PAGE_EXECUTE_READWRITE||p==PAGE_EXECUTE_WRITECOPY))return 0;
 return a+n<=(uintptr_t)m.BaseAddress+m.RegionSize;}
static uint32_t RU(uintptr_t a){return rdok(a,4)?*(uint32_t*)a:0;}
static int RI(uintptr_t a){return rdok(a,4)?*(int32_t*)a:0;}
static int heap(uint32_t v){return v>=0x400000u&&v<0x7F000000u;}
static int ent(uint32_t v){if(!heap(v)||!rdok(v,0x40))return 0;uint32_t t=*(uint32_t*)v;if(t<MODLO||t>=MODHI)return 0;
 int x=RI(v+OFF_X),y=RI(v+OFF_Y);return x>0x2000&&x<0xF000&&y>0x2000&&y<0xF000;}
static uint32_t gb=0;static int gl=0;
static int farr(uint32_t pl){if(gb&&rdok(gb,gl*4))for(int i=0;i<gl;i++)if(RU(gb+i*4)==pl)return 1;
 int bl=0;uint32_t bb=0;MEMORY_BASIC_INFORMATION m;uintptr_t a=0x10000;
 while(a<0x7F000000){if(VirtualQuery((LPCVOID)a,&m,sizeof(m))==0)break;uintptr_t b=(uintptr_t)m.BaseAddress,s=m.RegionSize;DWORD pr=m.Protect&0xFF;
  int ok=m.State==MEM_COMMIT&&!(m.Protect&PAGE_GUARD)&&(pr==PAGE_READWRITE||pr==PAGE_WRITECOPY||pr==PAGE_EXECUTE_READWRITE||pr==PAGE_EXECUTE_WRITECOPY);
  if(ok&&s<=0x4000000)for(uintptr_t p=b;p+4<=b+s;p+=4){if(*(uint32_t*)p!=pl)continue;uintptr_t ss=p,ee=p+4;
   while(ss-4>=b&&ent(*(uint32_t*)(ss-4)))ss-=4;while(ee+4<=b+s&&ent(*(uint32_t*)ee))ee+=4;int n=(int)((ee-ss)/4);if(n>bl){bl=n;bb=(uint32_t)ss;}}
  a=b+s;}
 if(bl>=3){gb=bb;gl=bl;return 1;}return 0;}
static uint32_t nearest(uint32_t pl,int px,int py){uint32_t best=0;long bd=1<<30;uint32_t seen[64];int ns=0;
 for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(RU(e+OFF_AI)==0)continue;
  int d=0;for(int k=0;k<ns;k++)if(seen[k]==e){d=1;break;}if(d)continue;if(ns<64)seen[ns++]=e;
  long dd=labs(RI(e+OFF_X)-px)+labs(RI(e+OFF_Y)-py);if(dd<bd){bd=dd;best=e;}}
 return best;}
/* 依 objid 在陣列中找該怪(仍存活才會在陣列裡) */
static uint32_t find_by_oid(uint32_t pl,uint32_t oid){
 for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(RU(e+OFF_AI)==0)continue;
  if(RU(e+OFF_ID)==oid)return e;}
 return 0;}
typedef void (__attribute__((cdecl)) *actfn_t)(int);
typedef void (__attribute__((cdecl)) *sendfn_t)(unsigned,int,int);
/* 主執行緒: 呼叫原生高階攻擊入口 */
static void do_native(uint32_t e){
 uint32_t pl=RU(PLAYER);if(!pl||!heap(e))return;
 uint32_t oid=RU(e+OFF_ID);
 if(rdok(TARGET,4))*(uint32_t*)TARGET=e;         /* 設當前目標 */
 if(rdok(HOVERSEL,4))*(uint32_t*)HOVERSEL=e;     /* 設選取候選 (模擬點擊) */
 L("[主] FUN_0040e790(怪0x%08X objid=0x%X @%d,%d)",e,oid,RI(e+OFF_X),RI(e+OFF_Y));
 actfn_t act=(actfn_t)FN_ACT;act((int)e);
 L("[主] 返回");
}
/* 主執行緒: 直接送 0x22 攻擊封包 (備援) */
static void do_send22(uint32_t e){
 if(!heap(e))return;uint32_t oid=RU(e+OFF_ID);
 if(rdok(TARGET,4))*(uint32_t*)TARGET=e;
 L("[主] 直送 0x22 (怪0x%08X objid=0x%X)",e,oid);
 sendfn_t snd=(sendfn_t)FN_SEND;snd(FMT_022,0x22,(int)oid);
 L("[主] 直送返回");
}
static HWND g_hw=0;static WNDPROC g_orig=0;static long g_bestA=0;
static LRESULT CALLBACK myproc(HWND h,UINT m,WPARAM w,LPARAM l){
 if(m==WM_ATK){do_native((uint32_t)w);return 0;}
 if(m==WM_S22){do_send22((uint32_t)w);return 0;}
 return CallWindowProcW(g_orig,h,m,w,l);}
static BOOL CALLBACK ecb(HWND h,LPARAM l){(void)l;DWORD pid;GetWindowThreadProcessId(h,&pid);
 if(pid==GetCurrentProcessId()&&IsWindowVisible(h)){RECT r;GetClientRect(h,&r);long ar=(long)r.right*r.bottom;
  if(r.right>=100&&r.bottom>=100&&ar>g_bestA){g_bestA=ar;g_hw=h;}}return TRUE;}
static int mode=0;      /* 單發: 1=native atk, 2=send22 */
static int hunt=0;      /* 自動打怪迴圈開關 */
static uint32_t lock_oid=0;  /* 鎖定中的怪 objid */
static void cmd(void){FILE*f=fopen(CMDPATH,"r");if(!f)return;char b[64]={0};fgets(b,64,f);fclose(f);remove(CMDPATH);
 if(strncmp(b,"hunt",4)==0){hunt=1;lock_oid=0;L("[CMD] hunt 開始自動打怪");}
 else if(strncmp(b,"stop",4)==0){hunt=0;L("[CMD] stop 停止");}
 else if(strncmp(b,"atk",3)==0){mode=1;L("[CMD] atk 單發");}
 else if(strncmp(b,"s22",3)==0){mode=2;L("[CMD] s22 直送0x22");}}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");L("==== onatk 啟動 pid=%lu ====",GetCurrentProcessId());
 Sleep(300);EnumWindows(ecb,0);
 if(g_hw){g_orig=(WNDPROC)SetWindowLongPtrW(g_hw,GWLP_WNDPROC,(LONG_PTR)myproc);
  L("已子類化視窗 0x%p (原WndProc=0x%p)",g_hw,g_orig);}else L("找不到視窗");
 int tick=0;
 for(;;){Sleep(150);cmd();
  /* 單發指令 */
  if(mode&&g_hw){int md=mode;mode=0;uint32_t pl=RU(PLAYER);if(pl&&farr(pl)){
   int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);uint32_t mo=nearest(pl,px,py);
   if(mo){L("[單發]最近怪0x%08X objid=0x%X @(%d,%d) 距(%d,%d)=%ld",mo,RU(mo+OFF_ID),RI(mo+OFF_X),RI(mo+OFF_Y),px,py,labs(RI(mo+OFF_X)-px)+labs(RI(mo+OFF_Y)-py));
    PostMessageW(g_hw,md==1?WM_ATK:WM_S22,(WPARAM)mo,0);}else L("[單發]找不到怪");}}
  /* 自動打怪迴圈: 每 ~600ms 對鎖定目標呼叫 FUN_0040e790 */
  if(hunt&&g_hw){tick++;if(tick>=4){tick=0;
   uint32_t pl=RU(PLAYER);if(!pl){continue;}if(!farr(pl)){continue;}
   int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);
   uint32_t e=lock_oid?find_by_oid(pl,lock_oid):0;
   if(!e){ e=nearest(pl,px,py); if(e){lock_oid=RU(e+OFF_ID);L("[獵] 換新目標 objid=0x%X",lock_oid);} }
   if(e){long dd=labs(RI(e+OFF_X)-px)+labs(RI(e+OFF_Y)-py);
    L("[獵] 目標0x%08X objid=0x%X @(%d,%d) 距(%d,%d)=%ld → FUN_0040e790",e,RU(e+OFF_ID),RI(e+OFF_X),RI(e+OFF_Y),px,py,dd);
    PostMessageW(g_hw,WM_ATK,(WPARAM)e,0);
   } else { L("[獵] 場上無怪"); }
  }}
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}
