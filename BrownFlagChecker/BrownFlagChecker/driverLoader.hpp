#pragma once

// Load the kernel driver

#include <Windows.h>
#include <stdio.h>
#include <Winternl.h>

#pragma comment(lib, "ntdll.lib")


typedef NTSTATUS(*_NtLoadDriver)(IN PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(*_NtUnloadDriver)(IN PUNICODE_STRING DriverServiceName);

static const char* regKeyName = "System\\CurrentControlSet\\Services\\BrownProtector";
static const wchar_t* wDriverKey = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\BrownProtector";
static const char* deviceLink = "\\\\.\\BrownProtectorDeviceLink";


bool loadDriver();

bool unloadDriver();
