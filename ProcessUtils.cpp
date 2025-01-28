#include "ProcessUtils.h"
#include "Logger.h"
#include <tlhelp32.h>

bool getModuleNameFromPID(DWORD pid, const std::string& dllName, std::string& foundDllPath, SIZE_T& dllSize, LPCVOID& baseAddress) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		logger.log(ERROR_T, "Failed to create snapshot.");
		return false;
	}

	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hSnapshot, &me32)) {
		logger.log(ERROR_T, "Failed to get first module.");
		CloseHandle(hSnapshot);
		return false;
	}

	do {
		if (dllName == me32.szModule) {
			foundDllPath = me32.szExePath;
			baseAddress = me32.modBaseAddr;
			dllSize = me32.modBaseSize;
			CloseHandle(hSnapshot);
			return true;
		}
	} while (Module32Next(hSnapshot, &me32));

	CloseHandle(hSnapshot);
	return false;
}