#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#pragma once

struct ProcInfo {
	DWORD id;
	HANDLE handle;
};

class Process {
	public:
		ProcInfo info;
		uintptr_t baseAddr;
		void init(const wchar_t* modName);
		template <typename ReadType> ReadType readMem(uintptr_t addr) {
			ReadType Data;
			if (ReadProcessMemory(this->info.handle, (LPVOID)(addr), &Data, sizeof(ReadType), 0)) {
				return Data;
			} else {
				ReadType ayy = { 0 };
				return ayy;
			}
		};
	private:
		ProcInfo findProcInfo(const wchar_t* modName);
		uintptr_t getModuleBaseAddr32(const wchar_t* modName, DWORD procId);
		uintptr_t getModuleBaseAddr64(const wchar_t* modName, DWORD procId);
};