/* oscan.c — 找實體的『螢幕座標快取欄位』
 * 玩家在客戶區中央(~225,211)。列出玩家/最近怪 物件內落在[0,500]的欄位, 找≈(225,211)的那組。
 * gcc -shared -O2 -s -o oscan.dll oscan.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#define PLAYER 0x00C2D2B8u
#define OFF_X 0x34
#define OFF_Y 0x38
#define OFF_AI 0x10
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\oscan.log"
#define MODLO 0x00400000u
#define MODHI 0x00F0B000u
static FILE*g;
static void L(const char*f,...){if(!g)return;va_list a;va_start(a,f);vfprintf(g,f,a);va_end(a);fputc('\n',g);fflush(g);}
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
static void dump(const char*tag,uint32_t e){
 L("---- %s 0x%08X 內落在[-50,500]的int欄位(螢幕座標候選) ----",tag,e);
 for(int o=0;o<0x140;o+=4){int v=RI(e+o);if(v>=-50&&v<=500)L("  +0x%03X = %d",o,v);}
}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");
 L("==== oscan (玩家中心~225,211) ====");
 for(int t=0;t<8;t++){Sleep(700);uint32_t pl=RU(PLAYER);if(!pl){L("未進場");continue;}
  if(!farr(pl)){L("無陣列");continue;}
  int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);
  uint32_t best=0;long bd=1<<30;uint32_t seen[64];int ns=0;
  for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(RU(e+OFF_AI)==0)continue;
   int d=0;for(int k=0;k<ns;k++)if(seen[k]==e){d=1;break;}if(d)continue;if(ns<64)seen[ns++]=e;
   long dd=labs(RI(e+OFF_X)-px)+labs(RI(e+OFF_Y)-py);if(dd<bd){bd=dd;best=e;}}
  L("===== 取樣 %d: 玩家世界(%d,%d) =====",t,px,py);
  dump("玩家",pl); if(best)dump("最近怪",best);
  break; /* 一次即可 */
 }
 return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}
