#ifndef INJ_H
#define INJ_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

int openProcAndExec(const char *pathToDLL, const char *processToInj);
HMODULE getModule(LPCWSTR moduleName);
void logError(const char* message);
HANDLE getHandleToProcessByName(const char* processName);

#ifdef __cplusplus
}
#endif

#endif