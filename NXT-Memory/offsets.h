#pragma once

//HHOOK hhk (SetWindowsHookEx)
const int off_MouseWindowHook = 0x72EDC0;

//WinMain DWORD* (above 0x2D000000500)
const int off_EngineBase = 0x72E6F8;

const int off_entity_X = 0xEC;
const int off_entity_Y = 0xF0;
const int off_entity_descAddr = 0x100;