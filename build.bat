@echo off
g++ -c .\c_dll\test_dll.cpp -o .\c_dll\test_dll.o
x86_64-w64-mingw32-gcc -shared .\c_dll\test_dll.o -o .\c_dll\outputfile.dll
ml64 /c /Zi .\syscalls.asm
IF ERRORLEVEL 1 (
    echo Do you have VisualStudio dev tools installed and PATH set to C:\Program Files\Microsoft Visual Studio\{...}\bin\Hostx64\x64 for ml.exe for use with MASM?
    exit /b
)
g++ -c -o inj.o inj.cpp -DUNICODE
g++ inj.o syscalls.obj -o inj.exe