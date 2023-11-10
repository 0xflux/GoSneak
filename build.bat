@echo off
gcc -c .\c_dll\test_dll.cpp
x86_64-w64-mingw32-gcc -shared .\c_dll\test_dll.o -o .\c_dll\outputfile.dll
g++ -c -o inj.o inj.cpp -DUNICODE
g++ inj.o -o inj.exe