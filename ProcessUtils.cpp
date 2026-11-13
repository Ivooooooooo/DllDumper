#include "ProcessUtils.h"

#include <cstring>
#include <tlhelp32.h>

#include "Logger.h"

namespace {

bool equalsIgnoreCase(const std::string& first, const std::string& second) {
	return first.size() == second.size() && _stricmp(first.c_str(), second.c_str()) == 0;
}

std::string fileNameOf(const std::string& path) {
	size_t pos = path.find_last_of("\\/");
	return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

HANDLE snapshotModules(DWORD pid) {
	HANDLE snapshot = INVALID_HANDLE_VALUE;
	DWORD error = ERROR_SUCCESS;

	// SNAPMODULE comes back with ERROR_BAD_LENGTH now and then while the target
	// is in the middle of loading something, so it's worth retrying
	for (int attempt = 0; attempt < 10; ++attempt) {
		snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
		if (snapshot != INVALID_HANDLE_VALUE) {
			return snapshot;
		}
		error = GetLastError();
		if (error != ERROR_BAD_LENGTH) {
			break;
		}
		Sleep(1);
	}

	logger.log(ERROR_T, "Could not read the module list of pid " + std::to_string(pid) + ": " + describeError(error));
	return INVALID_HANDLE_VALUE;
}

}

std::string describeError(DWORD code) {
	char* message = nullptr;
	DWORD length = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<char*>(&message),
		0,
		nullptr);

	std::string text = (length != 0 && message != nullptr)
		? std::string(message, length)
		: "error " + std::to_string(code);

	if (message != nullptr) {
		LocalFree(message);
	}

	while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ')) {
		text.pop_back();
	}
	return text;
}

bool enableDebugPrivilege() {
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		return false;
	}

	LUID luid;
	if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luid)) {
		CloseHandle(token);
		return false;
	}

	TOKEN_PRIVILEGES privileges{};
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL adjusted = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
	DWORD error = GetLastError();
	CloseHandle(token);

	// ERROR_NOT_ALL_ASSIGNED is what you get when the token is not elevated
	return adjusted != FALSE && error == ERROR_SUCCESS;
}

bool findProcessByName(const std::string& exeName, DWORD& pid) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		logger.log(ERROR_T, "CreateToolhelp32Snapshot failed: " + describeError(GetLastError()));
		return false;
	}

	const std::string wanted = fileNameOf(exeName);
	std::vector<DWORD> matches;

	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(entry);

	if (Process32First(snapshot, &entry)) {
		do {
			if (equalsIgnoreCase(entry.szExeFile, wanted)) {
				matches.push_back(entry.th32ProcessID);
			}
		} while (Process32Next(snapshot, &entry));
	}
	CloseHandle(snapshot);

	if (matches.empty()) {
		return false;
	}
	if (matches.size() > 1) {
		logger.log(WARNING, "There is more than one " + wanted + ", using pid " + std::to_string(matches.front()) + ".");
	}

	pid = matches.front();
	return true;
}

bool listModules(DWORD pid, std::vector<ModuleInfo>& modules) {
	HANDLE snapshot = snapshotModules(pid);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return false;
	}

	MODULEENTRY32 entry{};
	entry.dwSize = sizeof(entry);

	if (!Module32First(snapshot, &entry)) {
		logger.log(ERROR_T, "Module32First failed: " + describeError(GetLastError()));
		CloseHandle(snapshot);
		return false;
	}

	modules.clear();
	do {
		ModuleInfo module;
		module.name = entry.szModule;
		module.path = entry.szExePath;
		module.base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
		module.mappedSize = entry.modBaseSize;
		modules.push_back(module);
	} while (Module32Next(snapshot, &entry));

	CloseHandle(snapshot);
	return true;
}

bool findModule(DWORD pid, const std::string& name, ModuleInfo& module) {
	std::vector<ModuleInfo> modules;
	if (!listModules(pid, modules)) {
		return false;
	}

	// The same DLL can be loaded twice from different paths, in that case the
	// first one wins and we say so
	const std::string wanted = fileNameOf(name);
	const ModuleInfo* found = nullptr;

	for (const ModuleInfo& candidate : modules) {
		const bool nameMatches = equalsIgnoreCase(candidate.name, wanted);
		const bool pathMatches = equalsIgnoreCase(candidate.path, name);
		if (!nameMatches && !pathMatches) {
			continue;
		}
		if (found != nullptr) {
			logger.log(WARNING, "More than one module matches " + name + ", using " + found->path + ".");
			break;
		}
		found = &candidate;
	}

	if (found == nullptr) {
		logger.log(ERROR_T, name + " is not loaded in the process.");
		return false;
	}

	module = *found;
	return true;
}
