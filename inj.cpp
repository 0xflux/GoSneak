#include "inj.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <memory>
#include <random>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * to build, 64 bit only right now:
 * 
 * g++ -c -o inj.o inj.cpp -DUNICODE
 * ar rcs libinj.a inj.o
 * g++ inj.o -o inj.exe // for building just the c injector without go
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
 * @brief Retrieves the Process ID (PID) of a given process by its name.
 *
 * This function scans all processes currently running in the system to find a process
 * that matches the specified name. It creates a snapshot of all processes, iterates through
 * this list, and compares each process's name with the provided process name. If a match is found,
 * the function retrieves and returns the PID of that process.
 *
 * @param processName A string representing the name of the process to find.
 * @return DWORD Returns the process ID if found, NULL otherwise.
 */
DWORD getPidByName(const char* processName) {
    PROCESSENTRY32 entry; // stores process entry information
    entry.dwSize = sizeof(PROCESSENTRY32); // size of the structure
    char buf[MAX_PATH] = {}; // buffer to store the name of the executable
    size_t charsConverted = 0;

    // snapshot of all processes in the system
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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
                // open the process with all possible access rights
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(entry.th32ProcessID));
                if (hProcess != NULL) {
                    CloseHandle(snapshot); // close the snapshot handle as it is no longer needed
                    return entry.th32ProcessID; // return the process ID
                }
            }
        }
    }

    CloseHandle(snapshot); // close the snapshot handle if process not found
    logError("Target process not found");
    return 0; // return 0 if process not found
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
    size_t dllLength = strlen(dllPathToInject) + 1; // length including null terminator

    // get process ID of the target process
    DWORD pid = getPidByName(processToInj);
    if (pid == 0) {
        return -1;
    }

    // get handle to the Kernel32.dll and the address of LoadLibraryA
    HMODULE hK32 = GetModuleHandle(L"Kernel32");
    if (!hK32) {
        logError("Failed to get handle to Kernel32.dll");
        return -1;
    }
    FARPROC loadLibA_addr = GetProcAddress(hK32, "LoadLibraryA");
    if (!loadLibA_addr) {
        logError("Failed to get address of LoadLibraryA");
        return -1;
    }

    // open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        logError("Failed to open target process");
        return -1;
    }

    // allocate memory in the target process for the DLL path
    LPVOID alloc = VirtualAllocEx(hProcess, NULL, dllLength, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (alloc == NULL) {
        CloseHandle(hProcess);
        logError("Failed to allocate memory in target process");
        return -1; // return error if memory allocation fails
    }

    // write the DLL path to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, alloc, dllPathToInject, dllLength, NULL)) {
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        logError("Failed to write DLL path to process memory");
        return -1; // return error if writing to process memory fails
    }

    /**
     * Create a remote thread in the target process to load the DLL.
     * The function pointer LoadLibraryA is used as the starting address for the remote thread, and the allocated
     * memory (containing the DLL path) is passed as an argument to LoadLibraryA. This effectively loads the DLL into the target process.
    */
    HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibA_addr, alloc, 0, NULL);
    if (remoteThread == NULL) {
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        logError("Failed to create remote thread");
        return -1; // return error if thread creation fails
    }

    // wait for the remote thread to complete
    WaitForSingleObject(remoteThread, INFINITE);

    // clean up - close handles and free memory
    CloseHandle(remoteThread);
    VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}


#ifdef __cplusplus
}
#endif