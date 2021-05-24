#include <iostream>
#include <stdlib.h>
#include "process.h"
#include "offsets.h"
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
    std::cout << "Disabling RS3 mouse movement hook..." << std::endl;

    HHOOK hookHandle = proc.readMem<HHOOK>(off_MouseWindowHook);

    std::cout << "Found mouse hook handle: 0x" << std::hex << hookHandle << std::endl;

    if (hookHandle != (HHOOK)0x69696969 && !UnhookWindowsHookEx(hookHandle)) {
        std::cout << "Failed to unhook mouse handle." << std::endl;
        return false;
    }

    if (!proc.writeMem(off_MouseWindowHook, 0x69696969)) {
        std::cout << "Failed to replace mouse handle pointer." << std::endl;
        return false;
    }

    hookHandle = proc.readMem<HHOOK>(off_MouseWindowHook);

    if (hookHandle != (HHOOK)0x69696969) {
        std::cout << "Mouse handle pointer not replaced properly." << std::endl;
        return false;
    }

    std::cout << "Unhooked mouse handle: Now set to " << std::hex << hookHandle << std::endl;
    return true;
}