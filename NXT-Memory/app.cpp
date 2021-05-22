#include <iostream>
#include <stdlib.h>
#include "proc.h"

using namespace std;

static uintptr_t baseAddr;

int main() {
    cout << "Starting..." << endl;

    baseAddr = getModuleBaseAddr64(L"rs2client.exe");

    cout << "Found RS process: " << baseAddr << "!" << endl;

    return 0;
}
