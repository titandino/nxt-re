#pragma once

//HHOOK hhk (SetWindowsHookEx)
const char* off_windowsHookSig = "48 89 ? ? ? ? ? 80 BF B1 02 00 00";

//WinMain DWORD* (above 0x2D000000500)
const int off_engineBase = 0x72E6F8;

const int off_entity_x = 0xEC;
const int off_entity_y = 0xF0;
const int off_entity_serverIdx = 0x110;
const int off_entity_descAddr = 0x100;
const int off_entity_npcId = 0xF58;