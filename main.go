package main

/*
	@author 0xflux

	Main entry to the dll injector, which injects a Go based DLL into a process. Written in Go and C, wrapped with CGO.

	Example of running with commandline args:
	.\injector.exe -dll="C:\Users\gg\Desktop\telemetry.dll" -process='explorer.exe'
*/

/*
#cgo CXXFLAGS: -DUNICODE
#cgo LDFLAGS: ${SRCDIR}/../c_deps/libinj.a -lstdc++

#include <stdlib.h>
#include <stdint.h>
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
*/

import "C"
import (
	"flag"
	"fmt"
	"os"
	"unsafe"
)

var (
	userSelectedTargetProcess string
	userSelectedDLL           string
)

func main() {
	// read commandline args
	flag.StringVar(&userSelectedTargetProcess, "process", "", "process") // process at cli to inject into
	flag.StringVar(&userSelectedDLL, "dll", "", "dll")                   // full path at cli to dll to inject
	flag.Parse()

	// launch the loader
	loadDLLToRemoteProcess(userSelectedTargetProcess, userSelectedDLL)
}

func loadDLLToRemoteProcess(uProc string, uDll string) {
	if uProc == "" || uDll == "" {
		Log.Fatal("Please provide both flags -dll and -process args. Example usage: injector.exe -dll='C:\\Users\\gg\\Desktop\\telemetry.dll' -process='explorer.exe'")
	}

	var dllPath *C.char
	var procName *C.char

	// if the dll path doesnt exist throw error
	if _, err := os.Stat(uDll); os.IsNotExist(err) {
		Log.Fatalf("DLL path doesnt exist, %v", err) // handle this properly in the future
	} else if err != nil {
		Log.Fatalf("DLL path doesnt exist, %v", err) // handle this properly in the future
	}

	// assign dll path and process name as CStrings
	dllPath = C.CString(uDll)
	procName = C.CString(uProc)

	defer C.free(unsafe.Pointer(dllPath))
	defer C.free(unsafe.Pointer(procName))

	// open process from cli arg and inject dll
	result := C.openProcAndExec(dllPath, procName)

	if result == 0 {
		Log.Fatal("Fatal error from process injection.")
	} else {
		fmt.Printf("Successfully injected into process %s\n", uProc)
	}

}
