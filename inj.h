#ifndef INJ_H
#define INJ_H

#ifdef __cplusplus
extern "C" {
#endif

int openProcAndExec(const char *pathToDLL, const char *processToInj);

#ifdef __cplusplus
}
#endif

#endif