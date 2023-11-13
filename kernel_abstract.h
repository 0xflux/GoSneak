#pragma once

#include<Windows.h>
#include<stdio.h>

/**
 * Variables to store the SSN numbers of various NTDLL functions
*/

DWORD wNtAllocateVirtualMemory;
DWORD wNtWriteVirtualMemory;
DWORD wNtCreateThreadEx;
DWORD wNtWaitForSingleObject;
DWORD wNtOpenProcess;
DWORD wNtClose;


/**
 * Structures for our function prototypes to use for direct access to syscalls / ntdll
 * 
 * Good resources for structs:
 * https://www.vergiliusproject.com/ 
 * */

//0x30 bytes (sizeof)
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;                                                           //0x0
    VOID* RootDirectory;                                                    //0x8
    struct _UNICODE_STRING* ObjectName;                                     //0x10
    ULONG Attributes;                                                       //0x18
    VOID* SecurityDescriptor;                                               //0x20
    VOID* SecurityQualityOfService;                                         //0x28
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE {
	ULONGLONG Attribute;				/// PROC_THREAD_ATTRIBUTE_XXX | PROC_THREAD_ATTRIBUTE_XXX modifiers, see ProcThreadAttributeValue macro and Windows Internals 6 (372)
	SIZE_T Size;						/// Size of Value or *ValuePtr
	union {
		ULONG_PTR Value;				/// Reserve 8 bytes for data (such as a Handle or a data pointer)
		PVOID ValuePtr;					/// data pointer
	};
	PSIZE_T ReturnLength;				/// Either 0 or specifies size of data returned to caller via "ValuePtr"
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
	SIZE_T TotalLength;					/// sizeof(PS_ATTRIBUTE_LIST)
	PS_ATTRIBUTE Attributes[2];			/// Depends on how many attribute entries should be supplied to NtCreateUserProcess
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

//0x10 bytes (sizeof)
typedef struct _CLIENT_ID {
    PVOID              UniqueProcess;
    PVOID              UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


/**
 * Functions we are going to directly implement, for direct access to syscalls / ntdll
 * Bypassing EDR / antivirus hooking. 
 * 
 * Good resources for function prototypes: 
 * https://github.com/winsiderss/phnt/tree/7c1adb8a7391939dfd684f27a37e31f18d303944
 * 
 * */

extern "C" {
    // https://github.com/winsiderss/phnt/blob/7c1adb8a7391939dfd684f27a37e31f18d303944/ntpsapi.h#L2233
     NTSTATUS NtCreateThreadEx(
        _Out_       PHANDLE            ThreadHandle,
        _In_        ACCESS_MASK        DesiredAccess,
        _In_opt_    POBJECT_ATTRIBUTES ObjectAttributes,
        _In_        HANDLE             ProcessHandle,
        _In_        PVOID              StartRoutine,
        _In_opt_    PVOID              Argument,
        _In_        ULONG              CreateFlags,
        _In_        SIZE_T             ZeroBits,
        _In_        SIZE_T             StackSize,
        _In_        SIZE_T             MaximumStackSize,
        _In_opt_    PPS_ATTRIBUTE_LIST AttributeList
    );

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess
    NTSTATUS NtOpenProcess(
        _Out_       PHANDLE            ProcessHandle,
        _In_        ACCESS_MASK        DesiredAccess,
        _In_        POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_    PCLIENT_ID         ClientId
    );

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntclose
    NTSTATUS NtClose(
        _In_        HANDLE              Handle
    );

    // https://github.com/winsiderss/phnt/blob/7c1adb8a7391939dfd684f27a37e31f18d303944/ntmmapi.h#L536-L543
    NTSTATUS NtAllocateVirtualMemory(
        _In_        HANDLE              ProcessHandle,
        _Inout_ _At_ (*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
        _In_        ULONG_PTR           ZeroBits,
        _Inout_     PSIZE_T             RegionSize,
        _In_        ULONG               AllocationType,
        _In_        ULONG               Protect
    );

    // https://github.com/winsiderss/phnt/blob/7c1adb8a7391939dfd684f27a37e31f18d303944/ntmmapi.h#L599-L605
    NTSTATUS NtWriteVirtualMemory(
        _In_        HANDLE              ProcessHandle,
        _In_opt_    PVOID               BaseAddress,
        _In_reads_bytes_ (BufferSize)   PVOID Buffer,
        _In_        SIZE_T              BufferSize,
        _Out_opt_   PSIZE_T             NumberOfBytesWritten
        );

    // https://github.com/winsiderss/phnt/blob/7c1adb8a7391939dfd684f27a37e31f18d303944/ntobapi.h#L195
    NTSTATUS NtWaitForSingleObject(
        _In_ HANDLE Handle,
        _In_ BOOLEAN Alertable,
        _In_opt_ PLARGE_INTEGER Timeout
    );

}