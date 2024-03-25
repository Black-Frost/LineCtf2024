#pragma once
#include "driverLoader.hpp"
#include <ntstatus.h>

bool loadDriver() {
	// Ref: https://github.com/GitMirar/DriverLoader/blob/v0.2/DriverLoader/DriverLoader.cpp
	// Ref: https://github.com/FULLSHADE/DrvLoader/blob/main/Documentation.md
	const char* driverName = "BrownProtector.sys";
	char path[256];
	GetFullPathNameA(driverName, 256, path, NULL);

	// Setup registry keys
	HKEY hKey;
	LSTATUS regStat = RegCreateKeyExA(HKEY_LOCAL_MACHINE, regKeyName, NULL, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (regStat != ERROR_SUCCESS) {
		puts("Can't create registry key");
		return false;
	}

	// https://www.itprotoday.com/compute-engines/what-are-errorcontrol-start-and-type-values-under-services-subkeys#close-modal
	int dwData = 1;
	if (RegSetValueExA(hKey, "Type", 0, REG_DWORD, (BYTE*)&dwData, 4) != ERROR_SUCCESS) {
		return false;
	}

	// Manual start
	dwData = 3;
	if (RegSetValueExA(hKey, "Start", 0, REG_DWORD, (BYTE*)&dwData, 4) != ERROR_SUCCESS) {
		return false;
	}

	char driverPath[MAX_PATH];
	// Seems like "\\??\\" is the shortened form for "\DosDevice". Chatgpt was right!!
	// Ref: https://stackoverflow.com/questions/3580949/what-is-the-dosdevice
	// Ref: https://stackoverflow.com/questions/56941971/finding-windows-dos-device-file-paths
	// Ref: https://stackoverflow.com/questions/3544438/what-do-mean
	sprintf_s(driverPath, "%s%s", "\\??\\", path);
	if (RegSetValueExA(hKey, "ImagePath", 0, REG_EXPAND_SZ, (BYTE*)driverPath, strlen(driverPath) + 1) != ERROR_SUCCESS) {
		return false;
	}

	// Setup SeLoadDriverPrivilege
	LUID luid;
	if (!LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &luid)) {
		return false;
	}
	
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return false;
	}
	
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1; // only adjust one privilege
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	bool status = AdjustTokenPrivileges(hToken, false, &tp, 0, NULL, NULL);
	if (!status || GetLastError() != ERROR_SUCCESS) {
		//puts("Failed to aquire SeLoadDriverPrivilege");
		puts("User doesn't have permission to load driver");
		return false;
	}
	CloseHandle(hToken);

	// Load the driver
	HMODULE hNtdll = GetModuleHandleA("Ntdll.dll");
	if (hNtdll == 0) {
		return false;
	}
	_NtLoadDriver NtLoadDriver = (_NtLoadDriver)GetProcAddress(hNtdll, "NtLoadDriver");
	if (NtLoadDriver == nullptr) {
		return false;
	}
	UNICODE_STRING uDriverKey;
	RtlInitUnicodeString(&uDriverKey, wDriverKey);
	NTSTATUS loadStatus = NtLoadDriver(&uDriverKey);
	if (loadStatus == STATUS_SUCCESS) {
		//puts("DONE LOADING DRIVER");
		return true;
	}
	else {
		printf("NtLoadDriver failed with code: 0x%lx\n", loadStatus);
		return false;
	}
}

bool unloadDriver() {
	HMODULE hNtdll = GetModuleHandleA("Ntdll.dll");
	if (hNtdll == 0) {
		return false;
	}
	_NtUnloadDriver NtUnloadDriver = (_NtLoadDriver)GetProcAddress(hNtdll, "NtUnloadDriver");
	if (NtUnloadDriver == nullptr) {
		return false;
	}
	UNICODE_STRING uDriverKey{ 0 };
	RtlInitUnicodeString(&uDriverKey, wDriverKey);
	NTSTATUS unloadStatus = NtUnloadDriver(&uDriverKey);

	if (unloadStatus == STATUS_SUCCESS) {
		return true;
	}
	else {
		printf("NtUnloadDriver failed with code: 0x%lx\n", unloadStatus);
		return false;
	}

    return true;
}
