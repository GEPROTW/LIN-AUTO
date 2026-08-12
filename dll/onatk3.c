/* onatk3.c — 妖精弓手自動打怪 + 視線(牆)過濾
 * 使用者確認: 弓無距離限制, 但牆會擋箭/擋路 → 站定不走, 只打視線通暢的怪。
 * 地圖碰撞(反編譯 FUN_004f5910/FUN_004f4bd0):
 *   tile索引 = (y-[0xABF97C])*0x100 + x - [0xABF978]
 *   牆 = *(u16*)([0xABF4C0] + 4 + 索引*0x14) & 1
 * 指令 onatk3_cmd.txt:
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
#define LOGPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\onatk3.log"
#define CMDPATH "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\onatk3_cmd.txt"
#define MODLO 0x00400000u
#define MODHI 0x00F0B000u
#define FN_ACT  0x0040E790u
#define FN_SEND 0x00580E50u
#define FMT_022 0x008CAC24u
#define MINRANGE 4   /* 最小攻擊距離(格子): 貼身(格距<此值)的怪不打, 避免近戰崩潰 */
/* g_max(尋怪半徑) 也改成可即時調變數, 見下方 */
/* g_bow(開打射程) 與 g_view(畫面範圍) 改為可即時調整的變數, 見下方 g_bow / g_view */
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
static uint32_t gb=0;static int gl=0;static int use_los=1;  /* 視線過濾開關(los0/los1) */
static int g_bow=8;    /* 開打射程(格子): 進此範圍站定射. 指令 bow<n> 即時調 */
static int g_view=14;  /* 攻擊/鎖定範圍(格子): 只打此範圍內的怪(貼合可見區, 別太大). 指令 view<n> */
static int g_max=24;   /* 移動/追怪半徑(曼哈頓): 只在視窗內(800x600視野≈24)移動, 絕不走到視窗外座標(否則卡/崩). 指令 max<n> */
static int farr(uint32_t pl){if(gb&&rdok(gb,gl*4))for(int i=0;i<gl;i++)if(RU(gb+i*4)==pl)return 1;
 int bl=0;uint32_t bb=0;MEMORY_BASIC_INFORMATION m;uintptr_t a=0x10000;
 while(a<0x7F000000){if(VirtualQuery((LPCVOID)a,&m,sizeof(m))==0)break;uintptr_t b=(uintptr_t)m.BaseAddress,s=m.RegionSize;DWORD pr=m.Protect&0xFF;
  int ok=m.State==MEM_COMMIT&&!(m.Protect&PAGE_GUARD)&&(pr==PAGE_READWRITE||pr==PAGE_WRITECOPY||pr==PAGE_EXECUTE_READWRITE||pr==PAGE_EXECUTE_WRITECOPY);
  if(ok&&s<=0x4000000)for(uintptr_t p=b;p+4<=b+s;p+=4){if(*(uint32_t*)p!=pl)continue;uintptr_t ss=p,ee=p+4;
   while(ss-4>=b&&ent(*(uint32_t*)(ss-4)))ss-=4;while(ee+4<=b+s&&ent(*(uint32_t*)ee))ee+=4;int n=(int)((ee-ss)/4);if(n>bl){bl=n;bb=(uint32_t)ss;}}
  a=b+s;}
 if(bl>=3){gb=bb;gl=bl;return 1;}return 0;}
/* 最近的「距離<=g_max 且視線通暢且活著」怪. *outdd 帶回其距離 */
static uint32_t nearest_clear2(uint32_t pl,int px,int py,int want_clear,long*outdd){uint32_t best=0;long bd=1<<30;uint32_t seen[64];int ns=0;
 for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(!ent(e)||RU(e+OFF_AI)==0)continue;
  int d=0;for(int k=0;k<ns;k++)if(seen[k]==e){d=1;break;}if(d)continue;if(ns<64)seen[ns++]=e;
  if(!ismon(e))continue;                            /* 排除寵物/玩家/NPC(小objid) */
  if(!alive(e))continue;                           /* 排除死亡/屍體 */
  int mx=RI(e+OFF_X),my=RI(e+OFF_Y);
  if(cheb(px,py,mx,my)<MINRANGE)continue;          /* 貼身怪跳過(避免近戰崩潰) */
  long dd=labs(mx-px)+labs(my-py);
  if(dd>g_max)continue;                          /* 距離上限 */
  if(want_clear&&!los_clear(px,py,mx,my))continue; /* 視線過濾 */
  if(dd<bd){bd=dd;best=e;}}
 if(outdd)*outdd=best?bd:999;return best;}
static uint32_t nearest_clear(uint32_t pl,int px,int py,int want_clear){return nearest_clear2(pl,px,py,want_clear,0);}
/* 畫面內(格距<=g_view) 最近的視線通暢活真怪. *outch 帶回格子距離 */
static uint32_t nearest_view(uint32_t pl,int px,int py,int*outch){uint32_t best=0;int bch=9999;
 for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(!ent(e)||RU(e+OFF_AI)==0)continue;
  if(!ismon(e)||!alive(e))continue;int mx=RI(e+OFF_X),my=RI(e+OFF_Y);int ch=cheb(px,py,mx,my);
  if(ch<MINRANGE||ch>g_view)continue;if(use_los&&!los_clear(px,py,mx,my))continue;
  if(ch<bch){bch=ch;best=e;}}
 if(outch)*outch=best?bch:9999;return best;}
/* 依 objid 找該怪; 死亡/屍體視為找不到→立刻換下一隻 */
static uint32_t find_by_oid(uint32_t pl,uint32_t oid){
 for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(!ent(e)||RU(e+OFF_AI)==0)continue;
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
  for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(!ent(e)||RU(e+OFF_AI)==0)continue;
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
/* 純感知: 只列出真怪(排除寵物/玩家/NPC), 不攻擊不移動 */
static void sense(void){uint32_t pl=RU(PLAYER);if(!pl||!farr(pl)){L("[感知]未進場/無陣列");return;}
 load_map();int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);
 uint32_t seen[128];int ns=0,live=0,dead=0;
 for(int c=0;c<16;c++){uint32_t best=0;long bd=1<<30;
  for(int i=0;i<gl;i++){uint32_t e=RU(gb+i*4);if(!heap(e)||e==pl)continue;if(!ent(e)||RU(e+OFF_AI)==0)continue;
   if(!ismon(e))continue;                    /* 只看真怪(大objid) */
   int dup=0;for(int k=0;k<ns;k++)if(seen[k]==e){dup=1;break;}if(dup)continue;
   long dd=labs(RI(e+OFF_X)-px)+labs(RI(e+OFF_Y)-py);if(dd>200)continue;if(dd<bd){bd=dd;best=e;}}
  if(!best)break;if(ns<128)seen[ns++]=best;int a=alive(best);if(a)live++;else dead++;
  L("[感知]怪%d objid=0x%X 曼距=%ld 格距=%d 視線=%d %s",c,RU(best+OFF_ID),bd,
    cheb(px,py,RI(best+OFF_X),RI(best+OFF_Y)),los_clear(px,py,RI(best+OFF_X),RI(best+OFF_Y)),a?"活":"死屍");}
 L("[感知] 附近真怪: 活%d 隻, 死屍%d 隻 (只算真怪, 已排除寵物/玩家/NPC)",live,dead);}
/* 學習模式: 觀察玩家手動打怪(監看當前目標全域 [0xC2D2B4]), 記錄打法習慣, bot不出手 */
static uint32_t learn_last=0;static int learn_n=0,learn_maxch=0,learn_minch=999,learn_blk=0,learn_sumch=0;
static void learn_tick(void){uint32_t pl=RU(PLAYER);if(!pl||!farr(pl))return;load_map();
 int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);
 uint32_t tgt=rdok(TARGET,4)?*(uint32_t*)TARGET:0;
 if(!tgt||tgt==learn_last)return;
 if(!heap(tgt)||!ent(tgt)||!ismon(tgt)){return;}   /* 只學「打真怪」*/
 learn_last=tgt;int ch=cheb(px,py,RI(tgt+OFF_X),RI(tgt+OFF_Y));
 long man=labs(RI(tgt+OFF_X)-px)+labs(RI(tgt+OFF_Y)-py);
 int los=los_clear(px,py,RI(tgt+OFF_X),RI(tgt+OFF_Y));
 learn_n++;learn_sumch+=ch;if(ch>learn_maxch)learn_maxch=ch;if(ch<learn_minch)learn_minch=ch;if(!los)learn_blk++;
 L("[學習]你打 objid=0x%X 格距=%d 曼距=%ld 視線=%s",tgt,ch,man,los?"通暢":"隔牆");
 L("       統計: 共%d隻 | 格距 最近%d/最遠%d/平均%d | 隔牆打%d隻(%d%%)",
   learn_n,learn_minch,learn_maxch,learn_n?learn_sumch/learn_n:0,learn_blk,learn_n?learn_blk*100/learn_n:0);}
static int mode=0,hunt=0,sensing=0,learning=0;static uint32_t lock_oid=0;static int htick=0,ka=0;static int lastpx=0,lastpy=0;static int lostc=0;
static void cmd(void){FILE*f=fopen(CMDPATH,"r");if(!f)return;char b[64]={0};fgets(b,64,f);fclose(f);remove(CMDPATH);
 if(strncmp(b,"diag",4)==0){mode=9;L("[CMD]diag");}
 else if(strncmp(b,"sense",5)==0){sensing=1;hunt=0;learning=0;L("[CMD]sense 純感知模式(只列真怪, 不攻擊)");}
 else if(strncmp(b,"learn",5)==0){learning=1;hunt=0;sensing=0;learn_last=0;learn_n=0;learn_maxch=0;learn_minch=999;learn_blk=0;learn_sumch=0;L("[CMD]learn 學習模式開始(bot不出手, 請你手動打怪, 我記錄你的打法)");}
 else if(strncmp(b,"los0",4)==0){use_los=0;L("[CMD]視線過濾=關(打最近怪不管牆)");}
 else if(strncmp(b,"los1",4)==0){use_los=1;L("[CMD]視線過濾=開(只打視線通暢)");}
 else if(strncmp(b,"bow",3)==0){int v=atoi(b+3);if(v>=MINRANGE&&v<=80){g_bow=v;L("[CMD]開打射程 g_bow=%d 格",g_bow);}else L("[CMD]bow 數值需 %d~80",MINRANGE);}
 else if(strncmp(b,"view",4)==0){int v=atoi(b+4);if(v>=5&&v<=150){g_view=v;L("[CMD]攻擊範圍 g_view=%d 格",g_view);}else L("[CMD]view 數值需 5~150");}
 else if(strncmp(b,"max",3)==0){int v=atoi(b+3);if(v>=10&&v<=500){g_max=v;L("[CMD]尋怪半徑 g_max=%d",g_max);}else L("[CMD]max 數值需 10~500");}
 else if(strncmp(b,"hunt",4)==0){hunt=1;sensing=0;learning=0;lock_oid=0;L("[CMD]hunt 自動打怪(視線過濾=%d)",use_los);}
 else if(strncmp(b,"stop",4)==0){hunt=0;sensing=0;learning=0;L("[CMD]stop");}
 else if(strncmp(b,"s22",3)==0){mode=2;L("[CMD]s22 單發直送");}
 else if(strncmp(b,"atk",3)==0){mode=1;L("[CMD]atk 單發原生");}}
static DWORD WINAPI wk(LPVOID _){(void)_;g=fopen(LOGPATH,"a");L("==== onatk3 啟動 pid=%lu ====",GetCurrentProcessId());
 Sleep(300);EnumWindows(ecb,0);
 if(g_hw){g_orig=(WNDPROC)SetWindowLongPtrW(g_hw,GWLP_WNDPROC,(LONG_PTR)myproc);
  L("已子類化視窗0x%p (原=0x%p)",g_hw,g_orig);}else L("找不到視窗");
 int tick=0,stick=0;
 for(;;){Sleep(150);cmd();
  if(sensing){stick++;if(stick>=7){stick=0;sense();}}   /* 純感知: 每~1秒列出真怪, 不攻擊 */
  if(learning){learn_tick();}                           /* 學習: 每150ms 監看你手動打的目標 */
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
  if(hunt&&g_hw){htick++;if(htick>=2){htick=0;   /* 每~300ms 掃描 */
   uint32_t pl=RU(PLAYER);if(!pl)continue;if(!farr(pl))continue;load_map();
   int px=RI(pl+OFF_X),py=RI(pl+OFF_Y);
   int moving=(px!=lastpx||py!=lastpy);lastpx=px;lastpy=py;
   /* 每偵: 畫面內(格距<=g_view)最近的視線通暢活真怪 */
   int bch;uint32_t best=nearest_view(pl,px,py,&bch);
   /* 目前鎖定目標的有效性: 遠(可走近)或 近且視線通暢(可射) */
   uint32_t cur=lock_oid?find_by_oid(pl,lock_oid):0;
   int cch=cur?cheb(px,py,RI(cur+OFF_X),RI(cur+OFF_Y)):9999;
   long cman=cur?labs(RI(cur+OFF_X)-px)+labs(RI(cur+OFF_Y)-py):99999;
   int curValid=0;
   if(cur&&cch>=MINRANGE&&cman<=g_max){
    if(cch>g_bow)curValid=1;
    else if(!use_los||los_clear(px,py,RI(cur+OFF_X),RI(cur+OFF_Y)))curValid=1;
   }
   if(moving){ka=0;/* 移動中: 不送指令 */}
   else if(curValid){lostc=0;
    if(cch<=g_bow){ /* 進射程 */
     if(best&&RU(best+OFF_ID)!=lock_oid&&bch+4<=cch){lock_oid=RU(best+OFF_ID);ka=0;
      L("[獵]改打畫面近怪 objid=0x%X 格距=%d",lock_oid,bch);PostMessageW(g_hw,WM_ATK,(WPARAM)lock_oid,0);}
     else{ /* 維持連射: 每~1.8秒補點(避免自動連射中斷後怪打不死); 格距<6不補以免推進近戰 */
      if(cch>=6){ka++;if(ka>=6){ka=0;L("[獵]連射補點 objid=0x%X 格距=%d",lock_oid,cch);PostMessageW(g_hw,WM_ATK,(WPARAM)lock_oid,0);}}
      else ka=0;
     }
    } else { /* 走去接近 cur: 畫面內出現通暢怪就改打畫面怪, 否則繼續接近 */
     if(best&&RU(best+OFF_ID)!=lock_oid){lock_oid=RU(best+OFF_ID);ka=0;
      L("[獵]改打畫面怪 objid=0x%X 格距=%d",lock_oid,bch);PostMessageW(g_hw,WM_ATK,(WPARAM)lock_oid,0);}
     else{ka++;if(ka>=6){ka=0;L("[獵]接近補點 objid=0x%X 格距=%d",lock_oid,cch);PostMessageW(g_hw,WM_ATK,(WPARAM)lock_oid,0);}}
    }
   }
   else if(cur&&lostc<2){lostc++;/* 目標暫時失效(視線閃爍)寬限2偵, 避免抖動 */}
   else{ lostc=0;
    /* cur 無效(被牆擋/死/消失): 畫面內有通暢怪就打它(把攻擊從牆導開), 否則走去尋遠怪 */
    if(best){lock_oid=RU(best+OFF_ID);ka=0;
     L("[獵]畫面目標 objid=0x%X 格距=%d",lock_oid,bch);PostMessageW(g_hw,WM_ATK,(WPARAM)lock_oid,0);}
    else{ long rd;uint32_t r=nearest_clear2(pl,px,py,0,&rd);   /* 忽略視線, 最近活真怪 */
     if(r&&cheb(px,py,RI(r+OFF_X),RI(r+OFF_Y))>g_bow){lock_oid=RU(r+OFF_ID);ka=0;
      L("[獵]尋怪走向 objid=0x%X 曼距=%ld",lock_oid,rd);PostMessageW(g_hw,WM_ATK,(WPARAM)lock_oid,0);}
     else lock_oid=0;
    }
   }
  }}
 }return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}


