@echo off
g++ -c -o inj.o inj.cpp -DUNICODE
g++ inj.o -o inj.exe