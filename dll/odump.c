/* odump.c — in-process 自我 dump 模組映像(0x400000..0xF0B000)到檔案。
 * 因殼按需解密, 玩久後(滑鼠/攻擊/移動碼都執行過)再 dump, 映像更完整。
 * gcc -shared -O2 -s -o odump.dll odump.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#define LO 0x00400000u
#define HI 0x00F0B000u
#define OUT "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\tw_live.img"
#define LOGP "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\odump.log"
static int rdok(uintptr_t a,size_t n){MEMORY_BASIC_INFORMATION m;
 if(VirtualQuery((LPCVOID)a,&m,sizeof(m))==0)return 0;if(m.State!=MEM_COMMIT||(m.Protect&PAGE_GUARD))return 0;
 DWORD p=m.Protect&0xFF;if(p==PAGE_NOACCESS)return 0;
 return a+n<=(uintptr_t)m.BaseAddress+m.RegionSize;}
static DWORD WINAPI wk(LPVOID _){(void)_;
 FILE*lg=fopen(LOGP,"a");
 FILE*f=fopen(OUT,"wb");
 if(!f){if(lg){fprintf(lg,"開檔失敗\n");fflush(lg);}return 0;}
 uint32_t ok=0,zero=0; uint8_t z[0x1000]={0};
 for(uintptr_t a=LO;a<HI;a+=0x1000){
  if(rdok(a,0x1000)){fwrite((void*)a,1,0x1000,f);ok++;}
  else{fwrite(z,1,0x1000,f);zero++;}
 }
 fclose(f);
 if(lg){fprintf(lg,"dump 完成: ok頁=%u zero頁=%u -> %s\n",ok,zero,OUT);fflush(lg);fclose(lg);}
 return 0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x;if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);CreateThread(0,0,wk,0,0,0);}return TRUE;}
