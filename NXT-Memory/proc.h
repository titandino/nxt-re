#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

using namespace std;

DWORD findProcId(const wchar_t* modName);
uintptr_t getModuleBaseAddr32(const wchar_t* modName);
uintptr_t getModuleBaseAddr64(const wchar_t* modName);