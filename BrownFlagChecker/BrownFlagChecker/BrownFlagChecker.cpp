// ShadowMemUser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include <Windows.h>
#include <winnt.h>

#include "driverLoader.hpp"
#include "aes.hpp"
#include "sioctl.hpp"
#include "flag.hpp"
#include "cmd.hpp"
#include "BrownFlagChecker.hpp"

#define BUFFER_COUNT 20
#define PAGE_SIZE 4096

// Handle for child process;
HANDLE childProcHandle;
HANDLE childThreadHandle;
HANDLE childDevice = INVALID_HANDLE_VALUE;

HANDLE fatherDevice = INVALID_HANDLE_VALUE; // Handle to the file to send signal to driver
PVOID shadowBufferPtr[BUFFER_COUNT];

//const char* offsetArray[] = { "ABC", "DEF", "ATK", "SPE", "QRS", "EYE", "MOO", "DOG", "CAT", "BAT", "COW", "RED", "AIR", "WIN", "ZIP", "VIM", "CRY", "GUY", "ICE", "EGG"};

void cleanupFather() {
    if (fatherDevice != INVALID_HANDLE_VALUE) CloseHandle(fatherDevice);
    if (childProcHandle != INVALID_HANDLE_VALUE) CloseHandle(childProcHandle);
    if (childThreadHandle != INVALID_HANDLE_VALUE) CloseHandle(childThreadHandle);

    for (int i = 0; i < BUFFER_COUNT; i++) {
        VirtualFree(shadowBufferPtr[i], 0, MEM_RELEASE);
    }

    ExitProcess(0);
}

void cleanupChild() {
    if (childDevice != INVALID_HANDLE_VALUE) CloseHandle(childDevice);
    ExitProcess(0);
}

DWORD64 openMemory() {
    DWORD64 shadowIndex; 
    BOOL status = DeviceIoControl(childDevice, IOCTL_TURN_ON_SHADOW_BASE, NULL, 0, &shadowIndex, 8, NULL, NULL);
    //printf("SHADOWBASE: 0x%llx\n", shadowIndex << 39);
    if (!status) return -1;
    else return shadowIndex << 39;
}

void closeMemory() {
    DeviceIoControl(childDevice, IOCTL_TURN_OFF_SHADOW_BASE, NULL, 0, NULL, 0, NULL, NULL);
}


void runChild() {
    childDevice = CreateFileA(deviceLink, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);
    if (childDevice == INVALID_HANDLE_VALUE) {
        //puts("[!] Can't open device in child");
        cleanupChild();
    }

    DWORD64 regStatus;
    BOOL status = DeviceIoControl(childDevice, IOCTL_SHADOWMEM_REG_CHILD, NULL, 0, &regStatus, 8, NULL, NULL);
    if (!status || regStatus != SHADOWMEM_STAT_SUCCESS) cleanupChild();

    NANOMITE_CMD_INPUT();

    DWORD64 mappingStatus = 0;
    status = DeviceIoControl(childDevice, IOCTL_PREPARE_MAPPING, NULL, 0, &mappingStatus, 8, NULL, NULL);
    if (!status || mappingStatus == SHADOWMEM_STAT_FAIL) {
        cleanupChild();
    }

    if (checkKey()) {
        NANOMITE_CMD_CORRECT();
    }
    else {
        NANOMITE_CMD_WRONG();
    }
    cleanupChild();
}

bool handleDebugEvent(DEBUG_EVENT debugEvent) {
    switch (debugEvent.dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
        {
            childProcHandle = debugEvent.u.CreateProcessInfo.hProcess;
            childThreadHandle = debugEvent.u.CreateProcessInfo.hThread;
            if (!loadDriver()) {
                return false;
            }

            fatherDevice = CreateFileA(deviceLink, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);

            if (fatherDevice == INVALID_HANDLE_VALUE) {
                //puts("[!] Can't open device");
                return false;
            }
            DWORD64 regStatus;
            BOOL status = DeviceIoControl(fatherDevice, IOCTL_SHADOWMEM_REG_FATHER, NULL, 0, &regStatus, 8, NULL, NULL);

            if (!status || regStatus != SHADOWMEM_STAT_SUCCESS) return false;

            // This will contain the input later on
            const char data0[KEY_LEN] = { 188, 212, 252, 120, 165, 17, 251, 138, 212, 35, 208, 189, 53, 5, 33, 220 }; 
            const char data1[KEY_LEN] = { 158, 214, 103, 179, 141, 19, 141, 231, 73, 115, 82, 248, 180, 86, 248, 88 };   
            const char data2[KEY_LEN] = { 251, 167, 60, 163, 232, 141, 60, 116, 218, 203, 50, 132, 133, 236, 42, 237 };
            const char data3[KEY_LEN] = { 110, 49, 250, 85, 224, 57, 39, 250, 43, 144, 120, 182, 198, 114, 105, 223 };
            const char data4[KEY_LEN] = { 187, 189, 170, 69, 52, 207, 117, 202, 215, 211, 28, 19, 5, 62, 99, 78 };
            const char data5[KEY_LEN] = { 96, 58, 231, 123, 36, 218, 112, 111, 153, 42, 238, 178, 26, 150, 198, 51 };
            const char data6[KEY_LEN] = { 113, 41, 44, 14, 107, 47, 63, 47, 217, 113, 17, 178, 75, 99, 66, 244 };
            const char data7[KEY_LEN] = { 203, 221, 134, 62, 31, 3, 229, 47, 163, 177, 215, 244, 110, 168, 48, 208 };
            const char data8[KEY_LEN] = { 217, 174, 203, 90, 216, 252, 132, 243, 170, 197, 139, 157, 8, 45, 29, 143 };
            const char data9[KEY_LEN] = { 245, 209, 92, 90, 178, 233, 107, 33, 231, 44, 116, 250, 17, 0, 2, 220 };
            const char data10[KEY_LEN] = { 46, 68, 209, 132, 231, 5, 74, 122, 167, 103, 83, 138, 211, 202, 97, 217 };
            const char data11[KEY_LEN] = { 245, 24, 185, 114, 105, 76, 121, 204, 196, 19, 139, 224, 57, 102, 158, 89 };
            const char data12[KEY_LEN] = { 207, 116, 77, 239, 73, 187, 116, 170, 150, 110, 231, 245, 99, 9, 103, 137 };
            const char data13[KEY_LEN] = { 1, 80, 176, 96, 71, 226, 12, 246, 163, 189, 156, 65, 176, 97, 158, 52 };
            const char data14[KEY_LEN] = { 105, 158, 187, 97, 159, 171, 28, 20, 60, 142, 9, 195, 54, 252, 248, 248 };
            const char data15[KEY_LEN] = { 228, 73, 99, 112, 233, 54, 83, 141, 156, 20, 202, 240, 3, 188, 43, 61 };
            const char data16[KEY_LEN] = { 239, 175, 161, 68, 123, 200, 221, 248, 31, 156, 58, 248, 204, 194, 87, 139 };
            const char data17[KEY_LEN] = { 114, 94, 168, 77, 38, 71, 141, 175, 166, 142, 173, 155, 253, 190, 82, 111 };
            const char data18[KEY_LEN] = { 98, 78, 179, 48, 215, 99, 155, 148, 92, 236, 69, 21, 199, 245, 83, 88 };

            // Final buffer contains the expected value after encryption
            const char data19[KEY_LEN] = { 226, 66, 241, 66, 29, 42, 174, 199, 193, 236, 25, 106, 67, 69, 119, 226, 5, 211, 145, 227, 114, 89, 107, 170, 150, 65, 8, 77, 142, 145, 70, 243, 95, 134, 178, 42, 5, 178, 42, 138, 8, 155, 252, 102, 43, 7, 228, 61, 236, 87, 250, 28, 138, 253, 187, 8, 120, 6, 219, 120, 53, 79, 91, 224 };

            const char* dataArray[] = { data0, data1, data2, data3, data4, data5, data6, data7, data8, data9, data10,
                                        data11, data12, data13, data14, data15, data16, data17, data18, data19 };


            for (int i = 0; i < BUFFER_COUNT; i++) {
                // The pages are not actually created in physical memory
                // We have to write something to it so it could be created
                // Read more about this in the `Windows Internal` book, page 415, the section about virtual address descriptors
                shadowBufferPtr[i] = VirtualAlloc(NULL, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (shadowBufferPtr[i] == NULL) {
                    //puts("[!] Can't allocate buffer");
                    TerminateProcess(childProcHandle, 1);
                    return false;
                }
                memset(shadowBufferPtr[i], 0, 2048);
                memcpy(shadowBufferPtr[i], dataArray[i], KEY_LEN);
            }
        }
        break;

    case EXCEPTION_DEBUG_EVENT:
        if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_ALL;
            GetThreadContext(childThreadHandle, &ctx);

            switch (ctx.Rax)
            {
            case NANOMITE_CODE_INPUT:
                printf("Welcome! Give me the key and I will give you the flag: ");
                scanf_s("%128s", (char*)shadowBufferPtr[0]);
                if (strlen((char*)shadowBufferPtr[0]) != KEY_LEN) {
                    puts("Wrong! But here is a clue just for you: https://rb.gy/i6drqn");
                    TerminateProcess(childProcHandle, 0);
                    return false;
                }
                DeviceIoControl(fatherDevice, IOCTL_SHADOWMEM_SAVE_BUFFERS, shadowBufferPtr, sizeof(PVOID) * BUFFER_COUNT, NULL, 0, NULL, NULL);
                break;
            case NANOMITE_CODE_CORRECT:
                puts("Correct. Here is your flag");
                printFlag((char*)shadowBufferPtr[0]);
                break;
            case NANOMITE_CODE_WRONG:
                puts("Wrong! But here is a clue just for you: https://rb.gy/i6drqn");
                break;
            default:
                break;
            }
            ctx.Rax = 0;
            ctx.Rip += 6;
            SetThreadContext(childThreadHandle, &ctx);
        }
        else if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_ALL;
            GetThreadContext(childThreadHandle, &ctx);
            ctx.Rip += 8;
            SetThreadContext(childThreadHandle, &ctx);
        }
        break;

    case EXIT_PROCESS_DEBUG_EVENT:
        return false;
        break;
    default:
        break;
    }
    return true;
}

void runFather() {
    char filename[256];
    GetModuleFileNameA(NULL, filename, 256);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    BOOL child = CreateProcessA(filename, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);

    if (!child) {
        puts("[!] Can't create child process");
        return;
    }
    DEBUG_EVENT debugEvent;
    while (WaitForDebugEvent(&debugEvent, INFINITE)) {
        bool keepRunning = handleDebugEvent(debugEvent);
        if (keepRunning) ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
        else break;
    }
    CloseHandle(fatherDevice);
    unloadDriver();
    cleanupFather();
}

int main(int argc, char** argv)
{
    //puts("STARTING");
    if (IsDebuggerPresent()) {
        runChild();
    }
    else {
        runFather();
    }
    return 0;
}
