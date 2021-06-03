#include "app.h"

Process proc;

int main() {
    std::cout << "Starting..." << std::endl;
    std::cout << "Searching for rs2client module base..." << std::endl;

    proc.init(L"rs2client.exe");

    if (proc.info.id == 0) {
        std::cout << "Could not initialize process information." << std::endl;
        return 1;
    }

    std::cout << "Found RS3 process id: " << proc.info.id << "" << std::endl;
    std::cout << "Found RS3 process handle: " << proc.info.handle << "" << std::endl;
    std::cout << "Found RS3 base address: 0x" << std::hex << proc.baseAddr << "" << std::endl;

    //if (!disableMouseHook())
    //    return 1;

    //Address of signature = rs2client.exe + 0x004EFF51
    uintptr_t scan1 = proc.scan("48 89 ? ? ? ? ? 80 BF B1 02 00 00", 0x500000);

    std::cout << "Real windows hook address: " << std::hex << off_windowsHook << std::endl;
    std::cout << "Real windows hook address: " << std::hex << proc.readMem<HHOOK>(off_windowsHook) << std::endl;

    std::cout << "Scanned windows hook ASM address: " << std::hex << scan1 << std::endl;
    uintptr_t rip = scan1 + 7;
    std::cout << "rip: " << rip << std::endl;
    uintptr_t asmOff = proc.readAsmPtr(scan1 + 3);
    std::cout << "Scanned windows hook ASM data: " << std::hex << asmOff << std::endl;

    uintptr_t windowsHookScanned = rip + asmOff;
    std::cout << "Scanned windows hook pointer: " << std::hex << windowsHookScanned << std::endl;

    //Address of signature = rs2client.exe + 0x000018E4
    uintptr_t scan2 = proc.scan("48 8B ? ? ? ? ? E8 ? ? ? ? 48 8D ? ? ? ? ? 48 83 C4 ? E9 ? ? ? ? 4C 8B ? 48 83 EC ? 49 8D ? ? 49 89 ? ? 4C 8D ? ? ? ? ? 49 8D ? ? 49 89 ? ? 48 8D ? ? ? ? ? 49 8D ? ? 49 89 ? ? 49 8D ? ? 49 8D ? ? 49 89 ? ? C6 44 24 48 ? E8 ? ? ? ? 48 8B ? ? ? 48 8D ? ? ? ? ? 48 89 ? ? ? ? ? 48 89 ? ? ? ? ? 48 89 ? ? ? ? ? 48 8D ? ? ? ? ? 48 89 ? ? ? ? ? 48 8D ? ? ? ? ? 48 89 ? ? ? ? ? 48 89 ? ? ? ? ? 48 89 ? ? ? ? ? 48 8D ? ? ? ? ? 48 89 ? ? ? ? ? 48 8B ? ? ? 48 2B ? C6 05 5D B2 9A 00", 0x50000);

    std::cout << "Real offset: " << std::hex << 0x9a6830 << std::endl;

    std::cout << "Scanned offset ASM address: " << std::hex << scan2 << std::endl;
    uintptr_t rip2 = scan2 + 7;
    std::cout << "rip: " << rip2 << std::endl;
    uintptr_t asmOff2 = proc.readAsmPtr(scan2 + 3);
    std::cout << "Scanned offset ASM data: " << std::hex << asmOff2 << std::endl;

    uintptr_t offsetScanned = rip2 + asmOff2;
    std::cout << "Scanned offset pointer: " << std::hex << offsetScanned << std::endl;

    return 0;
}


bool disableMouseHook() {
    std::cout << "Disabling RS3 mouse hook..." << std::endl;

    HHOOK hookHandle = proc.readMem<HHOOK>(off_windowsHook);

    std::cout << "Found windows hook handle: 0x" << std::hex << hookHandle << std::endl;

    if (hookHandle != (HHOOK) 0x69696969 && !UnhookWindowsHookEx(hookHandle)) {
        std::cout << "Failed to unhook windows hook." << std::endl;
        return false;
    }

    if (!proc.writeMem(off_windowsHook, 0x69696969)) {
        std::cout << "Failed to replace windows hook pointer." << std::endl;
        return false;
    }

    hookHandle = proc.readMem<HHOOK>(off_windowsHook);

    if (hookHandle != (HHOOK) 0x69696969) {
        std::cout << "Windows hook pointer not replaced properly." << std::endl;
        return false;
    }

    std::cout << "Unhooked windows hook: Now set to " << std::hex << hookHandle << std::endl;
    return true;
}