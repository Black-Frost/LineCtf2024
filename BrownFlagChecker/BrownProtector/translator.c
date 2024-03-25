#include "translator.h"

BOOLEAN checkPagingMode() {
	CR0 cr0;
	CR4 cr4;
	cr0.flags = __readcr0();
	cr4.flags = __readcr4();

	// Dont handle 5-level paging
	if (cr0.paging_enable && !cr4.linear_addresses_57_bit) return TRUE;
	return FALSE;
}

DWORD64 virtualToPhysical(DWORD64 vAddr) {
	CR3 cr3 = {.flags = __readcr3()};
	VirtualAddressBits addressStruct = { .address = vAddr };
	PHYSICAL_ADDRESS pml4TablePhysical = {.QuadPart = cr3.flags & CR3_ADDRESS_OF_PAGE_DIRECTORY_FLAG };

	PML4E_64* pml4TableVirtual = (PML4E_64 *)MmGetVirtualForPhysical(pml4TablePhysical);
	PML4E_64 pml4e = pml4TableVirtual[addressStruct.pml4];

	PHYSICAL_ADDRESS pdpTablePhysical = { .QuadPart = pml4e.page_frame_number << 12};
	PDPTE_64* pdpTableVirtual = (PDPTE_64*)MmGetVirtualForPhysical(pdpTablePhysical);
	PDPTE_64 pdpte = pdpTableVirtual[addressStruct.directory_ptr];

	if (pdpte.large_page) {
		// 1GB page
		return (pdpte.flags & PDPTE_1GB_64_PAGE_FRAME_NUMBER_FLAG) | (vAddr & 0x3fffffff);
	}

	PHYSICAL_ADDRESS pdTablePhysical = { .QuadPart = pdpte.page_frame_number << 12 };
	PDE_64* pdTable = (PDE_64*)MmGetVirtualForPhysical(pdTablePhysical);
	PDE_64 pde = pdTable[addressStruct.directory];

	if (pde.large_page) {
		// 2MB page
		return (pde.flags & PDE_2MB_64_PAGE_FRAME_NUMBER_FLAG) | (vAddr & 0x1fffff);
	}

	PHYSICAL_ADDRESS pageTablePhysical = { .QuadPart = pde.page_frame_number << 12 };
	PTE_64* pageTableVirtual = (PTE_64*)MmGetVirtualForPhysical(pageTablePhysical);
	PTE_64 pte = pageTableVirtual[addressStruct.table];
	return (pte.page_frame_number << 12) | addressStruct.offset;
	//DbgPrint("CR3: 0x%llx - Virtual: 0x%llx\n", pml4TablePhysical.QuadPart, (DWORD64)pml4TableVirtual);
}

PML4E_64 createPagingPath(AddressPair* addrPairArray, DWORD64 len) {
	// Create a translation path (aka entries in paging tables) to get to the physical address
	// This will create a PML4 entry that contains every mapping between virtual and physical addresses in the addrPairArray

	PHYSICAL_ADDRESS higestPAddr = {.QuadPart = MAXULONG64 };

	PML4E_64 *pml4e = MmAllocateContiguousMemory(sizeof(PML4E_64), higestPAddr);
	allocationList[allocaionCount++] = (PVOID)pml4e;

	// Init the PML4 entry
	pml4e->flags = 0;
	pml4e->present = TRUE;
	pml4e->write = TRUE;
	pml4e->supervisor = TRUE;

	PDPTE_64* pdpTable = MmAllocateContiguousMemory(sizeof(PDPTE_64) * 512, higestPAddr);
	allocationList[allocaionCount++] = (PVOID)pdpTable;

	PHYSICAL_ADDRESS pdpTablePhysical = MmGetPhysicalAddress(pdpTable);
	memset(pdpTable, 0, sizeof(PDPTE_64) * 512);
	pml4e->page_frame_number = pdpTablePhysical.QuadPart >> 12;

	for (int i = 0; i < len; i++) {
		AddressPair pair = addrPairArray[i];

		// Virtual offset stored in the global map is encrypted, decryption is performed inline here;
		// Sneaky, but may cause frustration for player
		VirtualAddressBits addressStruct = { .address = pair.vAddr ^ 0x6969696969 };
		PHYSICAL_ADDRESS pAddr = { .QuadPart = pair.pAddr };
		//DbgPrint("Mapping: 0x%llx - 0x%llx\n", pair.vAddr ^ 0x6969696969, pair.pAddr);

		PDE_64* pdirTable;
		PHYSICAL_ADDRESS pdirTablePhysical;
		if (pdpTable[addressStruct.directory_ptr].flags == 0) {
			pdpTable[addressStruct.directory_ptr].present = TRUE;
			pdpTable[addressStruct.directory_ptr].write = TRUE;
			pdpTable[addressStruct.directory_ptr].supervisor = TRUE;

			pdirTable = MmAllocateContiguousMemory(sizeof(PDE_64) * 512, higestPAddr);
			allocationList[allocaionCount++] = (PVOID)pdirTable;
			memset(pdirTable, 0, sizeof(PDE_64) * 512);

			pdirTablePhysical = MmGetPhysicalAddress(pdirTable);
			pdpTable[addressStruct.directory_ptr].page_frame_number = pdirTablePhysical.QuadPart >> 12;
		}
		else {
			pdirTablePhysical.QuadPart = pdpTable[addressStruct.directory_ptr].page_frame_number << 12;
			pdirTable = MmGetVirtualForPhysical(pdirTablePhysical);

		}
		PTE_64* pageTable;
		PHYSICAL_ADDRESS pageTablePhysical;
		if (pdirTable[addressStruct.directory].flags == 0) {
			pdirTable[addressStruct.directory].present = TRUE;
			pdirTable[addressStruct.directory].write = TRUE;
			pdirTable[addressStruct.directory].supervisor = TRUE;

			pageTable = MmAllocateContiguousMemory(sizeof(PTE_64) * 512, higestPAddr);
			allocationList[allocaionCount++] = (PVOID)pageTable;
			memset(pageTable, 0, sizeof(PTE_64) * 512);

			pageTablePhysical = MmGetPhysicalAddress(pageTable);
			pdirTable[addressStruct.directory].page_frame_number = pageTablePhysical.QuadPart >> 12;
		}
		else {
			pageTablePhysical.QuadPart = pdirTable[addressStruct.directory].page_frame_number << 12;
			pageTable = MmGetVirtualForPhysical(pageTablePhysical);
		}

		if (pageTable[addressStruct.table].flags == 0) {
			pageTable[addressStruct.table].present = TRUE;
			pageTable[addressStruct.table].write = TRUE;
			pageTable[addressStruct.table].supervisor = TRUE;
			pageTable[addressStruct.table].page_frame_number = pair.pAddr >> 12;
		}
		else {
			//DbgPrint("Mapping already existed: 0x%llx - 0x%llx\n", pair.vAddr, pair.pAddr);
		}
	}

	return *pml4e;
}

DWORD64 insertPML4Entry(DWORD64 dirTableBase, PML4E_64 entry) {
	// Insert an entry into the specifed PML4 table
	// Return the index of the injected entry

	PHYSICAL_ADDRESS pml4Table = { .QuadPart = dirTableBase };
	PML4E_64* pml4TableVirtual = MmGetVirtualForPhysical(pml4Table);

	DWORD64 freeEntries[256] = { -1 };
	DWORD64 freeEntryNum = 0;
	// Find a free index
	// Only loop through user-mode pages (which is 0 to 256)
	// TODO: The entry should be chosen at random instead of first-fit ==> To prevent other processes from remote reading
	for (int i = 0; i < 256; i++) {
		if (pml4TableVirtual[i].flags == 0) {
			freeEntries[freeEntryNum++] = i;
		}
	}
	DWORD64 entryIndex = freeEntries[__rdtsc() % (freeEntryNum + 1)];
	pml4TableVirtual[entryIndex] = entry;
	return entryIndex;
}

void clearPML4Entry(DWORD64 dirTableBase, DWORD64 index) {
	PHYSICAL_ADDRESS pml4Table = { .QuadPart = dirTableBase };
	PML4E_64* pml4TableVirtual = MmGetVirtualForPhysical(pml4Table);
	pml4TableVirtual[index].flags = 0;
}
