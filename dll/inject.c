/* inject.c — 32-bit DLL 注入器 (CreateRemoteThread + LoadLibraryA)
 * 用法: inject.exe [dll路徑] [pid]
 *   不給 pid 時自動找 TWClient.bin。handle 開完即關(短命, 降低反作弊風險)。
 * 建置: gcc -m32 -O2 -s -o inject.exe inject.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <tlhelp32.h>

#define RESULT "C:\\Users\\pc\\orca\\LIN-AUTO\\dumps\\inject_result.txt"
static FILE *g_rf;
static void RL(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap); va_end(ap);
    if (g_rf) { va_list ap2; va_start(ap2, fmt); vfprintf(g_rf, fmt, ap2); va_end(ap2); fflush(g_rf); }
}

static DWORD findpid(const char *name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do { if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; } }
        while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int main(int argc, char **argv) {
    g_rf = fopen(RESULT, "w");
    const char *dll = (argc > 1) ? argv[1] : "C:\\Users\\pc\\orca\\LIN-AUTO\\dll\\ohunt.dll";
    DWORD pid = (argc > 2) ? (DWORD)atoi(argv[2]) : 0;
    if (!pid) pid = findpid("TWClient.bin");
    if (!pid) { RL("找不到 TWClient.bin 行程\n"); return 2; }
    RL("目標 pid=%lu  dll=%s\n", pid, dll);

    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                           PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                           FALSE, pid);
    if (!h) { RL("OpenProcess 失敗 err=%lu (需管理員?)\n", GetLastError()); return 3; }

    size_t len = strlen(dll) + 1;
    void *mem = VirtualAllocEx(h, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { RL("VirtualAllocEx 失敗 err=%lu\n", GetLastError()); CloseHandle(h); return 4; }

    SIZE_T wr = 0;
    if (!WriteProcessMemory(h, mem, dll, len, &wr)) {
        RL("WriteProcessMemory 失敗 err=%lu\n", GetLastError());
        VirtualFreeEx(h, mem, 0, MEM_RELEASE); CloseHandle(h); return 5;
    }
    FARPROC ll = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE t = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)ll, mem, 0, NULL);
    if (!t) { RL("CreateRemoteThread 失敗 err=%lu\n", GetLastError());
              VirtualFreeEx(h, mem, 0, MEM_RELEASE); CloseHandle(h); return 6; }

    RL("已送出注入, 等待 LoadLibrary...\n");
    WaitForSingleObject(t, 8000);
    DWORD ec = 0; GetExitCodeThread(t, &ec);
    RL("遠端 LoadLibraryA 回傳(hModule)=0x%08lX  => %s\n", ec, ec ? "注入成功" : "注入失敗");
    VirtualFreeEx(h, mem, 0, MEM_RELEASE);
    CloseHandle(t); CloseHandle(h);
    return ec ? 0 : 7;
}

