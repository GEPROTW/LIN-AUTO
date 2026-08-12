/* oclick.c — 自動點怪攻擊 (滑鼠, 用懸停全域自動命中)
 * [0x00ABF968]=游標下物件。移動游標搜尋(不移動角色), 當它==目標妖魔→左鍵點擊→真實攻擊。
 * 指令 oclick2_cmd.txt: "atk"=對最近怪自動點一次。
 * gcc -shared -O2 -s -o oclick.dll oclick.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#define PLAYER 0x00C2D2B8u
#define TARGET 0x00C2D2B4u
#define HOVER  0x00ABF968u
#define OFF_X 0x34
#define OFF_Y 0x38
#define OFF_AI 0x10
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\oclick2.log"
#define CMDPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\oclick2_cmd.txt"
#define MODLO 0x00400000u
#define MODHI 0x00F0B000u
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
static HWND g_hw=0; static long g_bestA=0;
static BOOL CALLBACK ecb(HWND h,LPARAM l){(void)l;DWORD pid;GetWindowThreadProcessId(h,&pid);
 if(pid==GetCurrentProcessId()&&IsWindowVisible(h)){RECT r;GetClientRect(h,&r);
  long area=(long)(r.right)*(r.bottom);
  if(r.right>=100&&r.bottom>=100){L("  候選視窗 0x%p client=%dx%d",h,r.right,r.bottom);
   if(area>g_bestA){g_bestA=area;g_hw=h;}}}
 return TRUE;}
static HWND findwin(void){g_hw=0;g_bestA=0;EnumWindows(ecb,0);return g_hw;}
static void clickat(int sx,int sy){SetCursorPos(sx,sy);Sleep(20);
 mouse_event(MOUSEEVENTF_LEFTDOWN,0,0,0,0);Sleep(40);mouse_event(MOUSEEVENTF_LEFTUP,0,0,0,0);}
/* 以客戶區中心為起點, 環狀由內而外搜尋游標位置, 直到 [HOVER]==target */
static int hover_search(HWND hw,uint32_t target,int*out_cx,int*out_cy){
 RECT rc;GetClientRect(hw,&rc);int W=rc.right,H=rc.bottom;POINT o={0,0};ClientToScreen(hw,&o);
 int ccx=W/2,ccy=H/2;
 for(int r=0;r<=120;r+=4){
  for(int a=0;a<360;a+=8){
   int cx=ccx+(int)(r*__builtin_cos(a*3.14159/180));
   int cy=ccy+(int)(r*__builtin_sin(a*3.14159/180));
   if(cx<0||cy<0||cx>=W||cy>=H)continue;
   SetCursorPos(o.x+cx,o.y+cy);Sleep(18);  /* 等遊戲下一幀更新懸停物件 */
   if(RU(HOVER)==target){*out_cx=cx;*out_cy=cy;return 1;}
  }
  if(r==0)r=0; /* 中心點只試一次 */
 }
 return 0;}
static int ticks=0;
static void cmd(void){FILE*f=fopen(CMDPATH,"r");if(!f)return;char b[64]={0};fgets(b,64,f);fclose(f);remove(CMDPATH);
 if(strncmp(b,"atk",3)==0){ticks=1;L("[CMD] atk");}}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");L("==== oclick 啟動 pid=%lu ====",GetCurrentProcessId());
 g_hw=findwin();
 {RECT r;POINT o={0,0};if(g_hw){GetClientRect(g_hw,&r);ClientToScreen(g_hw,&o);}
  L("選中遊戲視窗 hwnd=0x%p client=%dx%d 螢幕原點(%d,%d)",g_hw,g_hw?r.right:0,g_hw?r.bottom:0,o.x,o.y);}
 for(;;){Sleep(300);cmd();
  if(ticks>0){ticks--;
   uint32_t pl=RU(PLAYER);if(!pl){L("未進場");continue;}if(!farr(pl)){L("無陣列");continue;}
   int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);uint32_t m=nearest(pl,px,py);
   if(!m){L("找不到怪");continue;}
   L("目標妖魔 0x%08X @(%d,%d), 開始游標搜尋…",m,RI(m+OFF_X),RI(m+OFF_Y));
   int cx,cy;
   if(hover_search(g_hw,m,&cx,&cy)){
    L("★命中! 游標客戶區(%d,%d) [HOVER]==目標. 左鍵點擊攻擊!",cx,cy);
    RECT rc;POINT o={0,0};ClientToScreen(g_hw,&o);(void)rc;
    clickat(o.x+cx,o.y+cy);
    Sleep(200);
    uint32_t tg=RU(TARGET);
    L("點擊後 [目標0xC2D2B4]=0x%08X %s",tg,(tg==m)?"(==妖魔, 攻擊觸發!)":"");
   } else L("游標搜尋未命中(怪可能移動太快或在畫面外)");
  }
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}

