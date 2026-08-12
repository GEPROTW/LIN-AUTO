/* onatk3.c — 妖精弓手自動打怪 + 視線(牆)過濾
 * 使用者確認: 弓無距離限制, 但牆會擋箭/擋路 → 站定不走, 只打視線通暢的怪。
 * 地圖碰撞(反編譯 FUN_004f5910/FUN_004f4bd0):
 *   tile索引 = (y-[0xABF97C])*0x100 + x - [0xABF978]
 *   牆 = *(u16*)([0xABF4C0] + 4 + 索引*0x14) & 1
 * 指令 onatk16_cmd.txt:
 *   diag  = 只診斷(印地圖全域 + 玩家格 + 最近幾隻怪的距離/牆/視線), 不攻擊
 *   s22   = 對最近「視線通暢」怪直送 0x22 攻擊(不移動)
 *   atk   = 對最近「視線通暢」怪呼叫 FUN_0040e790(可能會移動接近)
 *   hunt  = 自動打怪迴圈(直送 0x22, 每~1秒, 站定不走)
 *   stop  = 停
 * gcc -shared -O2 -s -o onatk3.dll onatk3.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#define PLAYER 0x00C2D2B8u
#define TARGET 0x00C2D2B4u
#define HOVERSEL 0x00ABF440u
#define MAP_BASE 0x00ABF4C0u
#define MAP_OX 0x00ABF978u
#define MAP_OY 0x00ABF97Cu
#define OFF_X 0x34
#define OFF_Y 0x38
#define OFF_ID 0x0C
#define OFF_AI 0x10
#define OFF_STATE 0x14   /* 動作/狀態 char; ==8 代表死亡/不可互動(遊戲攻擊邏輯會跳過) */
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\onatk16.log"
#define CMDPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\onatk16_cmd.txt"
#define MODLO 0x00400000u
#define MODHI 0x00F0B000u
#define FN_ACT  0x0040E790u
#define FN_SEND 0x00580E50u
#define FMT_022 0x008CAC24u
#define MAXDIST 40   /* 交戰半徑: 曼哈頓距離 <= 此值的怪才追(避免跑遍全圖) */
#define BOWRANGE 10  /* 弓射程(格子距離 Chebyshev), 對齊 HOME 攻擊距離=10: 進此範圍就停下射, 不再補點 */
#define MINRANGE 4   /* 最小攻擊距離(格子): 貼身(格距<此值)的怪不打, 避免近戰崩潰 */
#define MON_MINID 0x01000000u  /* 怪物 objid 門檻: 玩家/寵物/NPC=小(~0x15xxxx), 怪物=大(~0x3B9xxxxx) */
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
static int RB(uintptr_t a){return rdok(a,1)?*(uint8_t*)a:8;}   /* 讀 byte; 讀不到當作死亡(8) */
static int alive(uint32_t e){return RB(e+OFF_STATE)!=8;}       /* +0x14==8 = 死亡/不可互動 */
static int cheb(int px,int py,int mx,int my){int ax=abs(mx-px),ay=abs(my-py);return ax>ay?ax:ay;} /* 格子距離 */
static int ismon(uint32_t e){return RU(e+OFF_ID)>=MON_MINID;}  /* 大objid=真怪; 排除寵物/玩家/NPC */
static int heap(uint32_t v){return v>=0x400000u&&v<0x7F000000u;}
static int ent(uint32_t v){if(!heap(v)||!rdok(v,0x40))return 0;uint32_t t=*(uint32_t*)v;if(t<MODLO||t>=MODHI)return 0;
 int x=RI(v+OFF_X),y=RI(v+OFF_Y);return x>0x2000&&x<0xF000&&y>0x2000&&y<0xF000;}
/* ---- 地圖牆壁 / 視線 ---- */
static uint32_t mbase,mox,moy;
static void load_map(void){mbase=RU(MAP_BASE);mox=RU(MAP_OX);moy=RU(MAP_OY);}
static int wall(int x,int y){
 if(!mbase)return 0;
 long idx=((long)(y-(int)moy))*0x100+(x-(int)mox);
 if(idx<0)return 1;
 uintptr_t a=mbase+4+(uintptr_t)idx*0x14;
 if(!rdok(a,2))return 1;
 return (*(uint16_t*)a)&1;
}
/* Bresenham: 玩家格→怪格, 中間任一格是牆 → 視線被擋(回0) */
static int los_clear(int x0,int y0,int x1,int y1){
 int dx=abs(x1-x0),dy=abs(y1-y0),sx=x0<x1?1:-1,sy=y0<y1?1:-1,err=dx-dy,x=x0,y=y0,guard=0;
 for(;;){
  if(!(x==x0&&y==y0)&&!(x==x1&&y==y1)){if(wall(x,y))return 0;}
  if(x==x1&&y==y1)break;
  int e2=2*err; if(e2>-dy){err-=dy;x+=sx;} if(e2<dx){err+=dx;y+=sy;}
  if(++guard>2000)break;
 }
 return 1;
}
/* ---- 怪陣列 ---- */
static uint32_t gb=0;static int gl=0;
static int farr(uint32_t pl){if(gb&&rdok(gb,gl*4))for(int i=0;i<gl;i++)if(RU(gb+i*4)==pl)return 1;
 int bl=0;uint32_t bb=0;MEMORY_BASIC_INFORMATION m;uintptr_t a=0x10000;
 while(a<0x7F000000){if(VirtualQuery((LPCVOID)a,&m,sizeof(m))==0)break;uintptr_t b=(uintptr_t)m.BaseAddress,s=m.RegionSize;DWORD pr=m.Protect&0xFF;
  int ok=m.State==MEM_COMMIT&&!(m.Protect&PAGE_GUARD)&&(pr==PAGE_READWRITE||pr==PAGE_WRITECOPY||pr==PAGE_EXECUTE_READWRITE||pr==PAGE_EXECUTE_WRITECOPY);
  if(ok&&s<=0x4000000)for(uintptr_t p=b;p+4<=b+s;p+=4){if(*(uint32_t*)p!=pl)continue;uintptr_t ss=p,ee=p+4;
   while(ss-4>=b&&ent(*(uint32_t*)(ss-4)))ss-=4;while(ee+4<=b+s&&ent(*(uint32_t*)ee))ee+=4;int n=(int)((ee-ss)/4);if(n>bl){bl=n;bb=(uint32_t)ss;}}
  a=b+s;}
 if(bl>=3){gb=bb;gl=bl;return 1;}return 0;}
/* 最近的「距離<=MAXDIST 且視線通暢且活著」怪. *outdd 帶回其距離 */
static uint32_t nearest_clear2(uint32_t pl,int px,int py,int want_clear,long*outdd){uint32_t best=0;long bd=1<<30;uint32_t seen[64];int ns=0;
 for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(RU(e+OFF_AI)==0)continue;
  int d=0;for(int k=0;k<ns;k++)if(seen[k]==e){d=1;break;}if(d)continue;if(ns<64)seen[ns++]=e;
  if(!ismon(e))continue;                            /* 排除寵物/玩家/NPC(小objid) */
  if(!alive(e))continue;                           /* 排除死亡/屍體 */
  int mx=RI(e+OFF_X),my=RI(e+OFF_Y);
  if(cheb(px,py,mx,my)<MINRANGE)continue;          /* 貼身怪跳過(避免近戰崩潰) */
  long dd=labs(mx-px)+labs(my-py);
  if(dd>MAXDIST)continue;                          /* 距離上限 */
  if(want_clear&&!los_clear(px,py,mx,my))continue; /* 視線過濾 */
  if(dd<bd){bd=dd;best=e;}}
 if(outdd)*outdd=best?bd:999;return best;}
static uint32_t nearest_clear(uint32_t pl,int px,int py,int want_clear){return nearest_clear2(pl,px,py,want_clear,0);}
/* 依 objid 找該怪; 死亡/屍體視為找不到→立刻換下一隻 */
static uint32_t find_by_oid(uint32_t pl,uint32_t oid){
 for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(RU(e+OFF_AI)==0)continue;
  if(RU(e+OFF_ID)==oid)return alive(e)?e:0;}return 0;}
typedef void (__attribute__((cdecl)) *actfn_t)(int);
typedef void (__attribute__((cdecl)) *sendfn_t)(unsigned,int,int);
/* 主執行緒: 收 objid, 攻擊前重新查怪是否還在(防 use-after-free) */
static uint32_t find_by_oid(uint32_t pl,uint32_t oid);
static void do_native(uint32_t oid){uint32_t pl=RU(PLAYER);if(!pl)return;
 uint32_t e=find_by_oid(pl,oid);if(!e||!ent(e)){L("[主]目標objid=0x%X已消失, 略過",oid);return;}
 if(rdok(TARGET,4))*(uint32_t*)TARGET=e;if(rdok(HOVERSEL,4))*(uint32_t*)HOVERSEL=e;
 L("[主]FUN_0040e790(怪0x%08X objid=0x%X)",e,oid);
 ((actfn_t)FN_ACT)((int)e);L("[主]返回");}
/* 最精簡攻擊: 只送 0x22 封包(不寫任何全域, 不移動). 弓手站著遠射。 */
static void do_send22(uint32_t oid){uint32_t pl=RU(PLAYER);if(!pl)return;
 uint32_t e=find_by_oid(pl,oid);if(!e||!ent(e)){L("[主]目標objid=0x%X已消失, 略過",oid);return;}
 L("[主]射擊0x22 objid=0x%X",oid);
 ((sendfn_t)FN_SEND)(FMT_022,0x22,(int)oid);}
static HWND g_hw=0;static WNDPROC g_orig=0;static long g_bestA=0;
static LRESULT CALLBACK myproc(HWND h,UINT m,WPARAM w,LPARAM l){
 if(m==WM_ATK){do_native((uint32_t)w);return 0;}
 if(m==WM_S22){do_send22((uint32_t)w);return 0;}
 return CallWindowProcW(g_orig,h,m,w,l);}
static BOOL CALLBACK ecb(HWND h,LPARAM l){(void)l;DWORD pid;GetWindowThreadProcessId(h,&pid);
 if(pid==GetCurrentProcessId()&&IsWindowVisible(h)){RECT r;GetClientRect(h,&r);long ar=(long)r.right*r.bottom;
  if(r.right>=100&&r.bottom>=100&&ar>g_bestA){g_bestA=ar;g_hw=h;}}return TRUE;}
/* 讀 name-ptr(+0x68) 指向的字串 */
static void rdname(uint32_t e,char*out,int n){out[0]=0;uint32_t np=RU(e+0x68);
 if(np&&rdok(np,1)){int i=0;for(;i<n-1&&rdok(np+i,1);i++){char c=*(char*)(np+i);if(c==0)break;out[i]=c;}out[i]=0;}}
/* 診斷: 印地圖 + 玩家 + 最近實體(名字/類別/是否有欄位指向玩家=主人→寵物) */
static void diag(void){uint32_t pl=RU(PLAYER);if(!pl){L("[診斷]未進場");return;}if(!farr(pl)){L("[診斷]無怪陣列");return;}
 load_map();int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);uint32_t pid=RU(pl+OFF_ID);
 L("[診斷]玩家 ptr=0x%08X objid=0x%X 類別[+CD]=%d (%d,%d)",pl,pid,RB(pl+0xCD),px,py);
 uint32_t seen[64];int ns=0;
 for(int c=0;c<10;c++){uint32_t best=0;long bd=1<<30;
  for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(RU(e+OFF_AI)==0)continue;
   int dup=0;for(int k=0;k<ns;k++)if(seen[k]==e){dup=1;break;}if(dup)continue;
   long dd=labs(RI(e+OFF_X)-px)+labs(RI(e+OFF_Y)-py);if(dd<bd){bd=dd;best=e;}}
  if(!best)break;if(ns<64)seen[ns++]=best;
  char nm[28];rdname(best,nm,28);
  /* 掃 +0x40..+0x160 找有沒有欄位 == 玩家ptr 或 玩家objid (=主人) */
  int own=-1;for(int o=0x40;o<=0x160;o+=4){uint32_t v=RU(best+o);if(v==pl||(pid&&v==pid)){own=o;break;}}
  L("[診斷]實體%d objid=0x%X 曼距=%ld 格距=%d 真怪=%d 視線=%d 活=%d 名[%s]",
    c,RU(best+OFF_ID),bd,cheb(px,py,RI(best+OFF_X),RI(best+OFF_Y)),ismon(best),
    los_clear(px,py,RI(best+OFF_X),RI(best+OFF_Y)),alive(best),nm);(void)own;}
}
static int mode=0,hunt=0;static uint32_t lock_oid=0;static int htick=0,ka=0;static int lastpx=0,lastpy=0;static int lostc=0;static int use_los=1;
static void cmd(void){FILE*f=fopen(CMDPATH,"r");if(!f)return;char b[64]={0};fgets(b,64,f);fclose(f);remove(CMDPATH);
 if(strncmp(b,"diag",4)==0){mode=9;L("[CMD]diag");}
 else if(strncmp(b,"los0",4)==0){use_los=0;L("[CMD]視線過濾=關(打最近怪不管牆)");}
 else if(strncmp(b,"los1",4)==0){use_los=1;L("[CMD]視線過濾=開(只打視線通暢)");}
 else if(strncmp(b,"hunt",4)==0){hunt=1;lock_oid=0;L("[CMD]hunt 自動打怪(視線過濾=%d)",use_los);}
 else if(strncmp(b,"stop",4)==0){hunt=0;L("[CMD]stop");}
 else if(strncmp(b,"s22",3)==0){mode=2;L("[CMD]s22 單發直送");}
 else if(strncmp(b,"atk",3)==0){mode=1;L("[CMD]atk 單發原生");}}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");L("==== onatk16 啟動 pid=%lu ====",GetCurrentProcessId());
 Sleep(300);EnumWindows(ecb,0);
 if(g_hw){g_orig=(WNDPROC)SetWindowLongPtrW(g_hw,GWLP_WNDPROC,(LONG_PTR)myproc);
  L("已子類化視窗0x%p (原=0x%p)",g_hw,g_orig);}else L("找不到視窗");
 int tick=0;
 for(;;){Sleep(150);cmd();
  if(mode){int md=mode;mode=0;
   if(md==9){diag();}
   else if(g_hw){uint32_t pl=RU(PLAYER);if(pl&&farr(pl)){load_map();int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);
    uint32_t mo=nearest_clear(pl,px,py,1);
    if(mo){L("[單發]最近通暢怪0x%08X objid=0x%X @(%d,%d) 距=%ld",mo,RU(mo+OFF_ID),RI(mo+OFF_X),RI(mo+OFF_Y),labs(RI(mo+OFF_X)-px)+labs(RI(mo+OFF_Y)-py));
     PostMessageW(g_hw,md==1?WM_ATK:WM_S22,(WPARAM)RU(mo+OFF_ID),0);}else L("[單發]無視線通暢的怪");}}}
  /* 自動打怪(認定專打+移動感知+死亡偵測):
     - 一旦開始打一隻怪就「認定」牠, 射擊中絕不切換 → 打到死才換(避免亂打)
     - 目標瞬間失效(視線閃爍)給3次寬限才放棄; 走去打途中出現近很多(>=8格)的怪才改道
     - 所有點擊只在角色「停下時」做(移動中送指令會衝突崩潰) */
  if(hunt&&g_hw){htick++;if(htick>=3){htick=0;   /* 每~450ms 檢查 */
   uint32_t pl=RU(PLAYER);if(!pl)continue;if(!farr(pl))continue;load_map();
   int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);
   int moving=(px!=lastpx||py!=lastpy);lastpx=px;lastpy=py;
   /* 評估鎖定目標是否仍有效(活/在交戰半徑/通暢). dch=格子距離(對齊HOME射程) */
   uint32_t e=lock_oid?find_by_oid(pl,lock_oid):0;   /* 死亡/消失→0 */
   long dd=999,dch=999;int valid=0;
   if(e){int mx=RI(e+OFF_X),my=RI(e+OFF_Y);dd=labs(mx-px)+labs(my-py);dch=cheb(px,py,mx,my);
    if(dd<=MAXDIST&&dch>=MINRANGE&&(!use_los||los_clear(px,py,mx,my)))valid=1;}
   if(lock_oid&&!valid){lostc++;if(lostc>=3){lock_oid=0;lostc=0;}}else lostc=0; /* 寬限3次才放棄 */
   if(moving){ka=0;/* 移動中: 維持現狀, 絕不送指令 */}
   else{
    if(lock_oid&&valid){
     if(dch<=BOWRANGE){ka=0;/* 進射程(格子距離)正在射: 認定專打, 不切換不補點 */}
     else{
      /* 走去打途中: 只有近很多(格子距離少6以上)的怪才改道, 否則繼續接近(卡住才補點) */
      long bd;uint32_t best=nearest_clear2(pl,px,py,use_los,&bd);
      long bch=best?cheb(px,py,RI(best+OFF_X),RI(best+OFF_Y)):999;
      if(best&&bch+6<=dch&&RU(best+OFF_ID)!=lock_oid){lock_oid=RU(best+OFF_ID);ka=0;lostc=0;
       L("[獵]改打近很多的怪 objid=0x%X 格距=%ld(原%ld)",lock_oid,bch,dch);PostMessageW(g_hw,WM_ATK,(WPARAM)lock_oid,0);}
      else{ka++;if(ka>=6){ka=0;L("[獵]接近補點 objid=0x%X 曼距=%ld 格距=%ld",lock_oid,dd,dch);PostMessageW(g_hw,WM_ATK,(WPARAM)lock_oid,0);}}
     }
    }
    else if(!lock_oid){
     /* 沒目標: 挑最近活怪(依 use_los 決定是否過濾視線), 認定牠 */
     long bd;uint32_t best=nearest_clear2(pl,px,py,use_los,&bd);
     if(best){lock_oid=RU(best+OFF_ID);ka=0;lostc=0;long bch=cheb(px,py,RI(best+OFF_X),RI(best+OFF_Y));
      L("[獵]新目標0x%08X objid=0x%X 曼距=%ld 格距=%ld →打到死",best,lock_oid,bd,bch);PostMessageW(g_hw,WM_ATK,(WPARAM)lock_oid,0);}
    }
    /* else: 鎖定中但暫時失效(寬限期)→ 靜候恢復 */
   }
  }}
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}

