# BusterCall
![Demo](image.png)
**HVCI bypass via PFN swapping to call arbitrary kernel functions from user-mode.**


***

## Overview

BusterCall demonstrates a technique to bypass Windows Hypervisor-protected Code Integrity (HVCI) by swapping the Page Frame Number (PFN) in a target PTE to redirect kernel code paths. The tool enables calling arbitrary exported kernel functions (e.g., `ExAllocatePool`, `DbgPrint`) from user-mode by hijacking the System Service Descriptor Table (SSDT) through physical memory manipulation.

***

## The Technique

HVCI enforces code integrity at the hypervisor level by validating page attributes in the PTE (R/W/X bits). The critical insight: **HVCI validates the attributes in the PTE, not the physical content behind it.** 

If the PFN in a PTE is modified to point to a different physical page, HVCI's checks are performed on the attributes of the original PTE (which remain unchanged), while the CPU fetches instructions from the swapped physical page.

### Attack Flow

1. **Identify Target**: Locate a read-only kernel page containing data you want to hijack (e.g., SSDT entries).
2. **Find Donor**: Locate a writable kernel page (e.g., from a driver `.data` section like `Beep.sys`).
3. **Copy**: Read the target page content, copy it to the donor page.
4. **Modify**: Edit the desired data in the donor page copy (e.g., replace an SSDT entry with a pointer to your target function).
5. **Swap PFN**: Modify the target's PTE to point to the donor's physical address.
6. **Trigger**: Invoke the syscall; the kernel walks the page tables and executes from your modified donor page.
7. **Restore**: Swap the original PFN back to clean up.

Because the donor page is legitimately writable, no HVCI violations occur when writing to it. The original protected page is never modified.

***

## Prerequisites

### Driver Primitive

This project requires kernel virtual memory read/write capabilities (e.g., an ASUS driver with physical memory write is used in the original implementation to gain virtual read/writes via PreviousMode exploit).

### NOTE

**Leaking kernel addresses on Windows 11 24H2+ requires `SeDebugPrivilege`.** Microsoft restricted `NtQuerySystemInformation` (and related APIs like `EnumDeviceDrivers`) in 24H2 via `ExIsRestrictedCaller`. Without this privilege, the API returns `STATUS_ACCESS_DENIED` for kernel pointer leaks. 

***

## Limitations

| Limitation | Details |
|------------|---------|
| **HLAT** | Not supported. Hypervisor-managed Linear Address Translation (Intel VT-rp) bypasses standard page table walks and uses hypervisor-managed paging structures. This attack targets standard PTE manipulation, which HLAT circumvents. |
| **TLB** | This PoC does not perform TLB invalidation. PFN swaps may not take effect immediately on all cores due to cached translations and also might cause BSODs. |
| **PatchGuard** | Changes are transient (restored after invocation), but be aware of unlucky race conditions. This is research code, not production weaponization. |

**I've addressed and provided some solutions for system-wide TLB flushing from usermode in**: [TLB Issue Soltution](https://github.com/zer0condition/BusterCall/issues/3#issuecomment-3865013737)
***

## Example

```cpp
if (!InitializeBusterCaller()) {
    printf("[-] Failed to initialize\n");
    return;
}

// Call DbgPrint from usermode
CallKernelFunction<NTSTATUS>("DbgPrint", "[BusterCall] Hello from kernel!\n");

// Allocate kernel pool memory
auto Pool = CallKernelFunction<PVOID>("ExAllocatePool", NonPagedPool, 0x1000);
printf("Allocated kernel pool: 0x%llx\n", Pool);

```

***

## Why This Works

HVCI validates PTE attributes at the hypervisor level via Second Level Address Translation (SLAT/EPT). It does not validate that the PFN in a PTE points to the "correct" physical page, it only checks that the attributes (R/W/X) are valid. By swapping the PFN while preserving the original PTE flags, the hypervisor sees a valid, unmodified page table entry, while the CPU executes from attacker-controlled physical memory.

**Caveat:** This technique targets the gap between VTL0 (NT kernel) and VTL1 (Hypervisor/Secure Kernel) page table enforcement. It assumes the hypervisor is not monitoring PTEs for PFN changes (which HLAT/HVPT addresses).

***

## References

- **HEXACON 2023** — [Viviane Zwanger and Henning Braun](https://www.youtube.com/watch?v=WWvd2_jd0ZI)
- **[superfetch](https://github.com/jonomango/superfetch)** — jonomango

## License
MIT
