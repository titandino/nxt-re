#include <iostream>
#include <stdlib.h>
#include "process.h"
#include "offsets.h"

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

    std::cout << "Disabling RS3 mouse movement hook..." << std::endl;

    uintptr_t hookHandle = proc.readMem<uintptr_t>(off_MouseWindowHook);

    std::cout << "Found mouse hook handle: 0x" << std::hex << hookHandle << std::endl;

    return 0;
}
