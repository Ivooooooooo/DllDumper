#ifndef PROCESS_UTILS_H
#define PROCESS_UTILS_H

#include <string>
#include <vector>
#include <Windows.h>

struct ModuleInfo {
	std::string name;     // file name as Toolhelp reports it
	std::string path;     // full path
	uintptr_t base = 0;
	SIZE_T mappedSize = 0;
};

std::string describeError(DWORD code);

bool enableDebugPrivilege();
bool findProcessByName(const std::string& exeName, DWORD& pid);
bool listModules(DWORD pid, std::vector<ModuleInfo>& modules);
bool findModule(DWORD pid, const std::string& name, ModuleInfo& module);

#endif // PROCESS_UTILS_H
