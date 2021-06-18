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

    if (!disableMouseHook())
        return 1;

    return 0;
}


bool disableMouseHook() {
    std::cout << "Disabling RS3 mouse hook..." << std::endl;

    uintptr_t asmAddr = proc.scan(off_windowsHookSig, 0x500000);
    uintptr_t windowsHookAddr = asmAddr + 7 + proc.readAsmPtr(asmAddr + 3); /*RIP + ASM Offset*/
    std::cout << "Scanned windows hook pointer: " << std::hex << windowsHookAddr << std::endl;
    std::cout << "Real windows hook address: " << std::hex << proc.readMem<HHOOK>(windowsHookAddr) << std::endl;

    HHOOK hookHandle = proc.readMem<HHOOK>(windowsHookAddr);

    std::cout << "Found windows hook handle: 0x" << std::hex << hookHandle << std::endl;

    if (hookHandle != (HHOOK) 0x69696969 && !UnhookWindowsHookEx(hookHandle)) {
        std::cout << "Failed to unhook windows hook." << std::endl;
        return false;
    }

    if (!proc.writeMem(windowsHookAddr, 0x69696969)) {
        std::cout << "Failed to replace windows hook pointer." << std::endl;
        return false;
    }

    hookHandle = proc.readMem<HHOOK>(windowsHookAddr);

    if (hookHandle != (HHOOK) 0x69696969) {
        std::cout << "Windows hook pointer not replaced properly." << std::endl;
        return false;
    }

    std::cout << "Unhooked windows hook: Now set to " << std::hex << hookHandle << std::endl;
    return true;
}