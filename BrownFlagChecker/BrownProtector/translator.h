#pragma once

// Translate from virtual address to physical address
// Also maybe handle direct mapping of physical pages

#include <ntddk.h>
#include <wdf.h>
#include <stdlib.h>

#include "ia32.h"

typedef union {
	struct {
		DWORD64 offset : 12;
		DWORD64 table : 9;
		DWORD64 directory : 9;
		DWORD64 directory_ptr : 9;
		DWORD64 pml4 : 9;
	};
	DWORD64 address;
} VirtualAddressBits;

typedef struct {
	DWORD64 vAddr;
	DWORD64 pAddr;
} AddressPair;

PVOID allocationList[256];
DWORD64 allocaionCount;

BOOLEAN checkPagingMode();

DWORD64 virtualToPhysical(DWORD64 vAddr);

PML4E_64 createPagingPath(AddressPair* addrPairArray, DWORD64 len);

DWORD64 insertPML4Entry(DWORD64 dirTableBase, PML4E_64 entry);

void clearPML4Entry(DWORD64 dirTableBase, DWORD64 index);