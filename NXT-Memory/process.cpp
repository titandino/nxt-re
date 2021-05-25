#include "process.h"

void Process::init(const wchar_t* modName) {
    this->info = findProcInfo(modName);
    this->baseAddr = getModuleBaseAddr64(modName, this->info.id);
}

uintptr_t Process::getModuleBaseAddr64(const wchar_t* modName, DWORD procId) {
	DWORD_PTR   baseAddress = 0;
	HANDLE      processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
	HMODULE* moduleArray;
	LPBYTE      moduleArrayBytes;
	DWORD       bytesRequired;

	if (processHandle) {
		if (EnumProcessModules(processHandle, NULL, 0, &bytesRequired)) {
			if (bytesRequired) {
				moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);

				if (moduleArrayBytes) {
					unsigned int moduleCount;

					moduleCount = bytesRequired / sizeof(HMODULE);
					moduleArray = (HMODULE*)moduleArrayBytes;

					if (EnumProcessModules(processHandle, moduleArray, bytesRequired, &bytesRequired)) {
						baseAddress = (DWORD_PTR)moduleArray[0];
					}

					LocalFree(moduleArrayBytes);
				}
			}
		}

		CloseHandle(processHandle);
	}

	return baseAddress;
}

uintptr_t Process::getModuleBaseAddr32(const wchar_t* modName, DWORD procId) {
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry)) {
            do {
                if (!_wcsicmp(modEntry.szModule, modName)) {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

ProcInfo Process::findProcInfo(const wchar_t* modName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    ProcInfo info = { 0 };

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap)
        return info;

    pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap); // clean the snapshot object
        printf("Failed to gather information on system processes! \n");
        return info;
    }

    do {
        if (!_wcsicmp(modName, pe32.szExeFile)) {
            info.id = pe32.th32ProcessID;
            info.handle = OpenProcess(PROCESS_ALL_ACCESS, NULL, info.id);
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return info;
}

char* Process::scanBasic(const char* pattern, const char* mask, char* begin, intptr_t size) {
    intptr_t patternLen = strlen(mask);

    for (int i = 0; i < size; i++) {
        bool found = true;
        for (int j = 0; j < patternLen; j++) {
            if (mask[j] != '?' && pattern[j] != *(char*)((intptr_t)begin + i + j)) {
                found = false;
                break;
            }
        }
        if (found)
            return (begin + i);
    }
    return nullptr;
}

uintptr_t Process::scan(const char* cPattern, intptr_t size) {
    char* match{ nullptr };
    SIZE_T bytesRead;
    DWORD oldprotect;
    char* buffer{ nullptr };
    MEMORY_BASIC_INFORMATION mbi;
    char pattern[100];
    char mask[100];
    mbi.RegionSize = 0x1000;

    parsePattern(cPattern, pattern, mask);

    VirtualQueryEx(this->info.handle, (LPCVOID)this->baseAddr, &mbi, sizeof(mbi));
    for (char* curr = (char*) this->baseAddr; curr < (char*) this->baseAddr + size; curr += mbi.RegionSize) {
        if (!VirtualQueryEx(this->info.handle, curr, &mbi, sizeof(mbi))) continue;
        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) continue;

        delete[] buffer;
        buffer = new char[mbi.RegionSize];

        if (VirtualProtectEx(this->info.handle, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldprotect)) {
            ReadProcessMemory(this->info.handle, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);
            VirtualProtectEx(this->info.handle, mbi.BaseAddress, mbi.RegionSize, oldprotect, &oldprotect);

            char* internalAddr = scanBasic(pattern, mask, buffer, (intptr_t) bytesRead);

            if (internalAddr != nullptr) {
                //calculate from internal to external
                match = curr + (internalAddr - buffer);
                break;
            }
        }
    }
    delete[] buffer;
    return (uintptr_t) (match - this->baseAddr);
}