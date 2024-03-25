#include "procChecker.h"

DWORD64 getCurrentImageBase() {
    UNICODE_STRING zwQueryInformationProcessName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
    _ZwQueryInformationProcess ZwQueryInformationProcess = (_ZwQueryInformationProcess)MmGetSystemRoutineAddress(&zwQueryInformationProcessName);
    PROCESS_BASIC_INFORMATION procInfoStruct;
    if (ZwQueryInformationProcess) {
        NTSTATUS stat = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &procInfoStruct, sizeof(PROCESS_BASIC_INFORMATION), NULL);
        char* peb = procInfoStruct.PebBaseAddress;
        DWORD64 imagebase = *(DWORD64*)(peb + 0x10);
        return imagebase;
    }
    return -1;
}

void getTextSection(DWORD64 imageBase, DWORD64* textBase, DWORD64* textSize) {
    *textBase = 0;
    *textSize = 0;
    //if (*((char*)imageBase) != 'M' || *((char*)imageBase + 1) != 'Z') return;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(imageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

    // DWORD is the signature
    DWORD64 sectionHeaderLocation = (DWORD64)ntHeaders + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeaders->FileHeader.SizeOfOptionalHeader;
    //DbgPrint("Offset: %lld\n", sectionHeaderLocation - imageBase);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(sectionHeaderLocation + sizeof(IMAGE_SECTION_HEADER) * i);
        if (strcmp(sectionHeader->Name, ".text") == 0) {
            *textBase = imageBase + sectionHeader->VirtualAddress;
            *textSize = sectionHeader->Misc.VirtualSize;
            return;
        }
    }
}

BOOLEAN checkIntegrity() {
    // Check if the .text section of the usermode process is not modified
    DWORD64 imagebase = getCurrentImageBase();
    if (imagebase == -1) return FALSE;
    DWORD64 textBase;
    DWORD64 textSize;
    getTextSection(imagebase, &textBase, &textSize);

    if (textBase == 0 || textSize == 0) return FALSE;
    DWORD32 crc32Hash = crc32_byte(textBase, textSize);
    //DbgPrint("Got crc32 hash: 0x%llx\n", crc32Hash);
    //return TRUE;
    return crc32Hash == EXPECTED_HASH;

}

BOOLEAN isBeingDebugged() {
    // Check if the current process is being debugged

    UNICODE_STRING zwQueryInformationProcessName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
    _ZwQueryInformationProcess ZwQueryInformationProcess = (_ZwQueryInformationProcess)MmGetSystemRoutineAddress(&zwQueryInformationProcessName);
    DWORD64 debugPort;
    if (ZwQueryInformationProcess) {
        NTSTATUS stat = ZwQueryInformationProcess(NtCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(DWORD64), NULL);
        //DbgPrint("%lx\n", stat);
        return debugPort != 0;
    }
    // If can't query information, return true by default
    return TRUE;
}

HANDLE getParentPid() {
    // Get the parent ID of the current process

    UNICODE_STRING zwQueryInformationProcessName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
    _ZwQueryInformationProcess ZwQueryInformationProcess = (_ZwQueryInformationProcess)MmGetSystemRoutineAddress(&zwQueryInformationProcessName);
    PROCESS_BASIC_INFORMATION procInfoStruct;
    if (ZwQueryInformationProcess) {
        NTSTATUS stat = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &procInfoStruct, sizeof(PROCESS_BASIC_INFORMATION), NULL);
        //DbgPrint("%lx\n", stat);
        return procInfoStruct.InheritedFromUniqueProcessId;
    }
    //else {
    //    DbgPrint("FAIL TO LOAD\n");
    //}
    return 0;
}