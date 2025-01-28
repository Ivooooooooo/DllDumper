#ifndef PROCESS_UTILS_H
#define PROCESS_UTILS_H

#include <windows.h>
#include <string>

bool getModuleNameFromPID(DWORD pid, const std::string& dllName, std::string& foundDllPath, SIZE_T& dllSize, LPCVOID& baseAddress);

#endif // PROCESS_UTILS_H