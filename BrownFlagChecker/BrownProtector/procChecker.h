#pragma once

//#include <winnt.h>
#include <Ntifs.h>
#include <Ntddk.h>
#include <wdf.h>
#include "peStruct.h"
#include "crc32.h"

#define EXPECTED_HASH 0x9eeeed36

#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00

typedef unsigned short      WORD;

// Handle anti-debug and integrity check of processes
typedef NTSTATUS(*_ZwQueryInformationProcess)(
    _In_      HANDLE           ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
    );

BOOLEAN checkIntegrity();

void getTextSection(DWORD64 imageBase, DWORD64* textBase, DWORD64* textSize);

BOOLEAN isBeingDebugged();

HANDLE getParentPid();
