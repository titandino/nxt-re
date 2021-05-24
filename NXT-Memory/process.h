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
			if (ReadProcessMemory(this->info.handle, (LPVOID)(this->baseAddr + addr), &Data, sizeof(ReadType), 0)) {
				return Data;
			} else {
				ReadType ayy = { 0 };
				return ayy;
			}
		};
		template <typename WriteType> bool writeMem(uintptr_t addr, WriteType val) {
			return WriteProcessMemory(this->info.handle, (LPVOID)(this->baseAddr + addr), &val, sizeof(WriteType), 0);
		};
	private:
		ProcInfo findProcInfo(const wchar_t* modName);
		uintptr_t getModuleBaseAddr32(const wchar_t* modName, DWORD procId);
		uintptr_t getModuleBaseAddr64(const wchar_t* modName, DWORD procId);
};