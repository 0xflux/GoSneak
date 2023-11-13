#ifndef INJ_H
#define INJ_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

int openProcAndExec(const char *pathToDLL, const char *processToInj);
HMODULE getModule(LPCWSTR moduleName);
void logPrintLn(const char* printType, const char* message);
HANDLE getHandleToProcessByName(const char* processName);
DWORD getSSN(IN HMODULE hNTDLL, IN LPCSTR NtFunction);
void printInfo(const char* message);
void printError(const char* message);


#ifdef __cplusplus
}
#endif

#endif