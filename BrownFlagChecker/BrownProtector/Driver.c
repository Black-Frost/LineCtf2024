#include <Ntifs.h>
#include <Ntddk.h>
#include <wdf.h>

#include "ia32.h"
#include "sioctl.h"
#include "translator.h"
#include "procChecker.h"

// Create device and symbolic link
UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\BrownProtectorDevice");
UNICODE_STRING linkName = RTL_CONSTANT_STRING(L"\\??\\BrownProtectorDeviceLink");

// Typedefs

// Global vars
HANDLE parentPid = 0;
HANDLE childPid = 0;
HANDLE childThreadId = 0;
BOOLEAN shadowRegionCreated = FALSE;
PML4E_64 fakePML4Entry;

DWORD64 currentShadowIndex = -1;
BOOLEAN isShadowMemOpen = FALSE;

PVOID obRegHandle;

// Keeping track of allocations from `translator.c`
//extern PVOID allocationList[256];
//extern DWORD64 allocaionCount;


#define BUFFER_COUNT 20
PVOID bufferPhysicalList[64] = { NULL };

DWORD64 vAddrList[BUFFER_COUNT] = { 0x6cfc3d1969, 0x6d3d5df969, 0x6d9d9db969, 0x6dbdfc0969, 0x6d1d9d2969, 0x6c2d7d5969, 
                                    0x6c5c4c7969, 0x6c6dfcc969, 0x6c2d7d4969, 0x6d3cfd3969, 0x6d0d3d2969, 0x6d3c6c5969, 
                                    0x6d8dfc1969, 0x6ddc2d7969, 0x6cfc4d5969, 0x6d5d4d7969, 0x6d2d3c4969, 0x6c4dfd7969, 
                                    0x6c1d9d5969, 0x6d1d1d3969
                                };

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
NTSTATUS HandleIoctl(PDEVICE_OBJECT, PIRP);
NTSTATUS HandleCreateClose(PDEVICE_OBJECT, PIRP);

OB_PREOP_CALLBACK_STATUS obPreOpCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    //Ref: https://github.com/MellowNight/Anti-debug/blob/master/Anti%20debug/register_callbacks.h#L137

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType == PsProcessType) {
        PEPROCESS targetProc = OperationInformation->Object;
        if (PsGetProcessId(targetProc) == childPid) {
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
        }

    }
    else if (OperationInformation->ObjectType == PsThreadType) {
        PETHREAD targetThread = OperationInformation->Object;
        if (PsGetThreadId(targetThread) == childThreadId) {
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
        }
    }
    return OB_PREOP_SUCCESS;
}

void obPostOpCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInformation);
    return;
}

NTSTATUS regHandleFilter() {
    // Protect the child from OpenThread() and OpenProcess()
    // Ref: https://github.com/MellowNight/Anti-debug/blob/master/Anti%20debug/register_callbacks.h#L137
    // Ref: https://community.osr.com/discussion/272579/obregistercallbacks-returning-access-denied
    // TODO: TEST THIS

    OB_CALLBACK_REGISTRATION obCallbackStruct;
    OB_OPERATION_REGISTRATION obOperationStructs[2];
    WCHAR altitudeStrBuf[32];

    // Protecting process handle
    obOperationStructs[0].ObjectType = PsProcessType;
    obOperationStructs[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOperationStructs[0].PreOperation = (POB_PRE_OPERATION_CALLBACK)obPreOpCallback;
    obOperationStructs[0].PostOperation = (POB_POST_OPERATION_CALLBACK)obPostOpCallback;

    obOperationStructs[1].ObjectType = PsThreadType;
    obOperationStructs[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOperationStructs[1].PreOperation = (POB_PRE_OPERATION_CALLBACK)obPreOpCallback;
    obOperationStructs[1].PostOperation = (POB_POST_OPERATION_CALLBACK)obPostOpCallback;

    //UNICODE_STRING altitudeStr = RTL_CONSTANT_STRING(L"420000");
    obCallbackStruct.Version = OB_FLT_REGISTRATION_VERSION;
    obCallbackStruct.OperationRegistrationCount = 2;
    obCallbackStruct.RegistrationContext = NULL;
    obCallbackStruct.OperationRegistration = obOperationStructs;
    //RtlInitUnicodeString(&obCallbackStruct.Altitude, L"420000");
    //KIRQL	oldIrql = KeRaiseIrqlToDpcLevel();

    obCallbackStruct.Altitude.Length = 0;
    obCallbackStruct.Altitude.MaximumLength = 32;
    obCallbackStruct.Altitude.Buffer = altitudeStrBuf;

    // Find a suitable altitude
    for (int i = 420000; i < 430000; i++) {
        //UNICODE_STRING altitudeStr;
        RtlZeroMemory(obCallbackStruct.Altitude.Buffer, obCallbackStruct.Altitude.Length);
        RtlIntegerToUnicodeString((ULONG)i, 10, &obCallbackStruct.Altitude);
        NTSTATUS status = ObRegisterCallbacks(&obCallbackStruct, &obRegHandle);
        //DbgPrint("Obreg status: 0x%llx\n", status);
        //return STATUS_SUCCESS;
        if (status == STATUS_SUCCESS) return STATUS_SUCCESS;
        else if (status == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION) continue;
        else return status;
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    RegistryPath
)
{
    // Ref: https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/sending-commands-from-userland-to-your-kernel-driver-using-ioctl
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleIoctl;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = HandleCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = HandleCreateClose;

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DriverObject->DeviceObject);

    if (!NT_SUCCESS(status)) {
        DbgPrint(("Could not create the device object\n"));
        return status;
    }
    allocaionCount = 0;
    status = IoCreateSymbolicLink(&linkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint(("Could not create symlink\n"));
        return status;
    }

    return status;
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DriverObject);

    for (int i = 0; i < allocaionCount; i++) {
        MmFreeContiguousMemory(allocationList[i]);
    }

    IoDeleteSymbolicLink(&linkName);
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    if (obRegHandle) ObUnRegisterCallbacks(obRegHandle);
    //DbgPrint("Unloaded\n");
    return;
}

NTSTATUS HandleCreateClose(PDEVICE_OBJECT DriverObject, PIRP Irp) {
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DriverObject);

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;

}

NTSTATUS HandleIoctl(PDEVICE_OBJECT DriverObject, PIRP Irp) {
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DriverObject);

    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    DWORD64 inBufLength = ioStack->Parameters.DeviceIoControl.InputBufferLength;
    DWORD64 outBufLength = ioStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (ioStack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_SHADOWMEM_REG_FATHER:
    {
        if (parentPid == 0) {
            childPid = 0;
            childThreadId = 0;
            shadowRegionCreated = FALSE;
            parentPid = PsGetCurrentProcessId();
            if (checkIntegrity() && !isBeingDebugged() && checkPagingMode()) {
                *(DWORD64*)Irp->AssociatedIrp.SystemBuffer = SHADOWMEM_STAT_SUCCESS;
                //DbgPrint("Registered %lld as parent\n", parentPid);
            }
            else {
                parentPid = 0;
                *(DWORD64*)Irp->AssociatedIrp.SystemBuffer = SHADOWMEM_STAT_FAIL;
                //DbgPrint("Rejected %lld as parent\n", parentPid);
            }
        }
        else {
            *(DWORD64*)Irp->AssociatedIrp.SystemBuffer = SHADOWMEM_STAT_FAIL;
        }
        Irp->IoStatus.Information = 8;
    }
    break;

    case IOCTL_SHADOWMEM_REG_CHILD:
    {
        if (getParentPid() == parentPid) {
            childPid = PsGetCurrentProcessId();
            childThreadId = PsGetCurrentThreadId();

            if (regHandleFilter() == STATUS_SUCCESS) {
                *(DWORD64*)Irp->AssociatedIrp.SystemBuffer = SHADOWMEM_STAT_SUCCESS;
            }
            else {
                *(DWORD64*)Irp->AssociatedIrp.SystemBuffer = SHADOWMEM_STAT_FAIL;
            }
        }
        else {
            *(DWORD64*)Irp->AssociatedIrp.SystemBuffer = SHADOWMEM_STAT_FAIL;
        }
        Irp->IoStatus.Information = 8;
    }
    break;

    case IOCTL_SHADOWMEM_SAVE_BUFFERS:
    {
        if (PsGetCurrentProcessId() == parentPid && checkIntegrity() && !isBeingDebugged()) {
            PVOID* recvData = (PVOID*)Irp->AssociatedIrp.SystemBuffer;
            for (int i = 0; i < inBufLength / sizeof(PVOID*); i++) {
                DWORD64 pAddr = virtualToPhysical(recvData[i]);
                bufferPhysicalList[i] = pAddr;
            }
        }
        // No bytes is transfered back to userland
        Irp->IoStatus.Information = 0;
    }
    break;
    case IOCTL_PREPARE_MAPPING:
    {
        if (PsGetCurrentProcessId() == childPid && PsGetCurrentThreadId() == childThreadId && !shadowRegionCreated) {
            AddressPair pairList[BUFFER_COUNT];
            DWORD64 pairCount = 0;
            for (int i = 0; i < BUFFER_COUNT; i++) {
                DWORD64 pAddr = bufferPhysicalList[i];
                DWORD64 vAddr = vAddrList[i];
                if (pAddr == 0) continue;
                // Virtual address at this stage is still xored with 0x6969696969. It will be decrypted inside createPagingPath
                AddressPair pair = { .pAddr = pAddr, .vAddr = vAddr };
                pairList[pairCount++] = pair;
            }

            // Create our custom entries and save it for later
            fakePML4Entry = createPagingPath(pairList, pairCount);
            *(DWORD64*)Irp->AssociatedIrp.SystemBuffer = SHADOWMEM_STAT_SUCCESS;
            shadowRegionCreated = TRUE;
            Irp->IoStatus.Information = 8;
        }
        else {
            *(DWORD64*)Irp->AssociatedIrp.SystemBuffer = SHADOWMEM_STAT_FAIL;
            Irp->IoStatus.Information = 8;
        }
    }
    break;

    case IOCTL_TURN_ON_SHADOW_BASE:
    {
        //DbgPrint("Got opening memory request\n");
        if (PsGetCurrentProcessId() == childPid && PsGetCurrentThreadId() == childThreadId && shadowRegionCreated && checkIntegrity()) {
            if (!isShadowMemOpen) {
                CR3 cr3 = { .flags = __readcr3() };
                currentShadowIndex = insertPML4Entry(cr3.address_of_page_directory << 12, fakePML4Entry);
                isShadowMemOpen = TRUE;
            }
            *(DWORD64*)Irp->AssociatedIrp.SystemBuffer = currentShadowIndex;
            Irp->IoStatus.Information = 8;
        } 
    }
    break;

    case IOCTL_TURN_OFF_SHADOW_BASE:
    {
        if (PsGetCurrentProcessId() == childPid && PsGetCurrentThreadId() == childThreadId && isShadowMemOpen) {
            CR3 cr3 = { .flags = __readcr3() };
            clearPML4Entry(cr3.address_of_page_directory << 12, currentShadowIndex);
            currentShadowIndex = -1;
            isShadowMemOpen = FALSE;
        }
    }
    break;

    default:
    break;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

