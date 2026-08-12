/* oatk.c — 攻擊觸發測試 DLL (32-bit)
 * 指令檔 oatk_cmd.txt 寫 "atk" → 找最近妖魔, 把其指標寫入 [0xC2D2B4](當前目標),
 * 並維持數秒, 觀察角色是否自動攻擊。若不夠, 之後再加攻擊觸發函數呼叫。
 * gcc -shared -O2 -s -o oatk.dll oatk.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#define PLAYER 0x00C2D2B8u
#define TARGET 0x00C2D2B4u
#define OFF_X 0x34
#define OFF_Y 0x38
#define OFF_AI 0x10
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\oatk.log"
#define CMDPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\oatk_cmd.txt"
#define MODLO 0x00400000u
#define MODHI 0x00F0B000u
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
static int heap(uint32_t v){return v>=0x400000u&&v<0x7F000000u;}
static int ent(uint32_t v){if(!heap(v)||!rd(v,0x40))return 0;uint32_t t=*(uint32_t*)v;
 if(t<MODLO||t>=MODHI)return 0;int x=RI(v+OFF_X),y=RI(v+OFF_Y);
 return x>0x2000&&x<0xF000&&y>0x2000&&y<0xF000;}
static uint32_t gb=0;static int gl=0;
static int farr(uint32_t pl){if(gb&&rd(gb,gl*4))for(int i=0;i<gl;i++)if(RU(gb+i*4)==pl)return 1;
 int bl=0;uint32_t bb=0;MEMORY_BASIC_INFORMATION m;uintptr_t a=0x10000;
 while(a<0x7F000000){if(VirtualQuery((LPCVOID)a,&m,sizeof(m))==0)break;
  uintptr_t b=(uintptr_t)m.BaseAddress,s=m.RegionSize;DWORD pr=m.Protect&0xFF;
  int ok=m.State==MEM_COMMIT&&!(m.Protect&PAGE_GUARD)&&(pr==PAGE_READWRITE||pr==PAGE_WRITECOPY||pr==PAGE_EXECUTE_READWRITE||pr==PAGE_EXECUTE_WRITECOPY);
  if(ok&&s<=0x4000000)for(uintptr_t p=b;p+4<=b+s;p+=4){if(*(uint32_t*)p!=pl)continue;
   uintptr_t ss=p,ee=p+4;while(ss-4>=b&&ent(*(uint32_t*)(ss-4)))ss-=4;while(ee+4<=b+s&&ent(*(uint32_t*)ee))ee+=4;
   int n=(int)((ee-ss)/4);if(n>bl){bl=n;bb=(uint32_t)ss;}}
  a=b+s;}
 if(bl>=3){gb=bb;gl=bl;return 1;}return 0;}
/* 找最近的怪(有AI, 非自己) */
static uint32_t nearest(uint32_t pl,int px,int py){uint32_t best=0;long bd=1<<30;
 uint32_t seen[64];int ns=0;
 for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(RU(e+OFF_AI)==0)continue;
  int dup=0;for(int k=0;k<ns;k++)if(seen[k]==e){dup=1;break;}if(dup)continue;if(ns<64)seen[ns++]=e;
  long d=labs(RI(e+OFF_X)-px)+labs(RI(e+OFF_Y)-py);if(d<bd){bd=d;best=e;}}
 return best;}
static int atk_ticks=0;static uint32_t atk_tgt=0;
static void cmd(void){FILE*f=fopen(CMDPATH,"r");if(!f)return;char b[64]={0};fgets(b,64,f);fclose(f);remove(CMDPATH);
 if(strncmp(b,"atk",3)==0){atk_ticks=25;L("[CMD] atk → 開始設定目標實驗");}}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");L("==== oatk 啟動 pid=%lu ====",GetCurrentProcessId());
 for(;;){Sleep(200);cmd();uint32_t pl=RU(PLAYER);if(!pl)continue;if(!farr(pl))continue;
  int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);
  if(atk_ticks>0){atk_ticks--;
   if(!atk_tgt||!rd(atk_tgt,0x40)){atk_tgt=nearest(pl,px,py);
    if(atk_tgt)L("目標選定: 怪 0x%08X @(%d,%d)",atk_tgt,RI(atk_tgt+OFF_X),RI(atk_tgt+OFF_Y));}
   if(atk_tgt&&rd(TARGET,4)){uint32_t old=RU(TARGET);*(uint32_t*)TARGET=atk_tgt;
    if(old!=atk_tgt)L("寫入 [0xC2D2B4]=0x%08X (原=0x%08X)",atk_tgt,old);}
   if(atk_ticks==0){L("實驗結束(維持約5秒)。角色有無自動攻擊?");atk_tgt=0;}
  }
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}

