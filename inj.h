#ifndef INJ_H
#define INJ_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

int openProcAndExec(const char *pathToDLL, const char *processToInj);
HMODULE getModule(LPCWSTR moduleName);

#ifdef __cplusplus
}
#endif

#endif