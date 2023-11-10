#include <windows.h>

// C++ DLL 1) gcc -c test_dll.cpp, 2) x86_64-w64-mingw32-gcc -shared test_dll.o -o outputfile.dll
BOOL APIENTRY DllMain(
            HMODULE hModule,
            DWORD ul_reason_for_call,
            LPVOID lpReserved
        )
{

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "gg lets goooo!", "GG", NULL);
    
    default:
        break;
    }
    return TRUE;
}