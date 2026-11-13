#include "ProcessUtils.h"

#include <cstring>
#include <tlhelp32.h>

#include "Logger.h"

namespace {

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

Bitness machineBitness(USHORT machine) {
	switch (machine) {
	case IMAGE_FILE_MACHINE_I386: return Bitness::X86;
	case IMAGE_FILE_MACHINE_AMD64: return Bitness::X64;
	case IMAGE_FILE_MACHINE_ARM64: return Bitness::Arm64;
	default: return Bitness::Unknown;
	}
}

struct UnicodeString64 {
	USHORT length;
	USHORT maximumLength;
	ULONG padding;
	ULONG64 buffer;
};

struct ProcessBasicInformation64 {
	ULONG64 reserved1;
	ULONG64 pebBaseAddress;
	ULONG64 reserved2[2];
	ULONG64 uniqueProcessId;
	ULONG64 reserved3;
};

// Offsets of the 64-bit PEB and LDR structures, they have not moved in years
constexpr Address kPebLdr = 0x18;
constexpr Address kLdrInLoadOrder = 0x10;
constexpr Address kEntryDllBase = 0x30;
constexpr Address kEntrySizeOfImage = 0x40;
constexpr Address kEntryFullDllName = 0x48;
constexpr Address kEntryBaseDllName = 0x58;

std::string utf16ToUtf8(const std::wstring& text) {
	if (text.empty()) {
		return std::string();
	}

	const int length = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
	std::string result(static_cast<size_t>(length), '\0');
	WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &result[0], length, nullptr, nullptr);
	return result;
}

bool readUnicodeString64(const RemoteMemory& memory, Address address, std::wstring& text) {
	UnicodeString64 value{};
	if (!memory.read(address, &value, sizeof(value))) {
		return false;
	}
	if (value.length == 0 || value.length > 2048 || value.buffer == 0) {
		return false;
	}

	std::wstring wide(value.length / sizeof(wchar_t), L'\0');
	if (!memory.read(value.buffer, &wide[0], value.length)) {
		return false;
	}

	text = wide;
	return true;
}

// Toolhelp gives back a 32-bit PEB when a WOW64 process asks about a 64-bit one, so
// the module list has to come from the real PEB instead
bool listModulesFromPeb64(const RemoteMemory& memory, std::vector<ModuleInfo>& modules) {
	using NtWow64QueryInformationProcess64Fn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

	static const NtWow64QueryInformationProcess64Fn queryProcess = reinterpret_cast<NtWow64QueryInformationProcess64Fn>(
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64QueryInformationProcess64"));

	if (queryProcess == nullptr) {
		return false;
	}

	ProcessBasicInformation64 info{};
	ULONG returned = 0;
	if (queryProcess(memory.process(), 0, &info, sizeof(info), &returned) < 0 || info.pebBaseAddress == 0) {
		logger.log(ERROR_T, "Could not read the 64-bit PEB of the target.");
		return false;
	}

	Address ldr = 0;
	if (!memory.readPointer(info.pebBaseAddress + kPebLdr, ldr) || ldr == 0) {
		return false;
	}

	const Address listHead = ldr + kLdrInLoadOrder;
	Address current = 0;
	if (!memory.readPointer(listHead, current)) {
		return false;
	}

	modules.clear();
	for (int guard = 0; guard < 4096 && current != 0 && current != listHead; ++guard) {
		Address dllBase = 0;
		Address sizeOfImage = 0;
		if (!memory.readPointer(current + kEntryDllBase, dllBase) ||
			!memory.readPointer(current + kEntrySizeOfImage, sizeOfImage)) {
			break;
		}

		ModuleInfo module;
		module.base = dllBase;
		module.mappedSize = static_cast<SIZE_T>(sizeOfImage);

		std::wstring fullName;
		std::wstring baseName;
		readUnicodeString64(memory, current + kEntryFullDllName, fullName);
		readUnicodeString64(memory, current + kEntryBaseDllName, baseName);

		module.path = utf16ToUtf8(fullName);
		module.name = utf16ToUtf8(baseName);
		if (module.name.empty() && !module.path.empty()) {
			module.name = fileNameOf(module.path);
		}

		if (dllBase != 0) {
			modules.push_back(module);
		}

		Address next = 0;
		if (!memory.readPointer(current, next)) {
			break;
		}
		current = next;
	}

	return !modules.empty();
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

const char* bitnessName(Bitness bitness) {
	switch (bitness) {
	case Bitness::X86: return "x86";
	case Bitness::X64: return "x64";
	case Bitness::Arm64: return "arm64";
	default: return "unknown";
	}
}

Bitness selfBitness() {
	return sizeof(void*) == 8 ? Bitness::X64 : Bitness::X86;
}

Bitness processBitness(HANDLE process) {
	using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

	// Loaded by hand so the binary still starts on systems without it
	static const IsWow64Process2Fn isWow64Process2 = reinterpret_cast<IsWow64Process2Fn>(
		GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process2"));

	if (isWow64Process2 != nullptr) {
		USHORT processMachine = 0;
		USHORT nativeMachine = 0;
		if (isWow64Process2(process, &processMachine, &nativeMachine) != FALSE) {
			// UNKNOWN means the process is not being emulated, so it runs as the
			// machine the system is
			return machineBitness(processMachine == IMAGE_FILE_MACHINE_UNKNOWN ? nativeMachine : processMachine);
		}
	}

	BOOL wow64 = FALSE;
	if (IsWow64Process(process, &wow64) != FALSE && wow64 != FALSE) {
		return Bitness::X86;
	}
	return Bitness::Unknown;
}

bool sameName(const std::string& first, const std::string& second) {
	return first.size() == second.size() && _stricmp(first.c_str(), second.c_str()) == 0;
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
			if (sameName(entry.szExeFile, wanted)) {
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

bool listModulesForTarget(const RemoteMemory& memory, DWORD pid, std::vector<ModuleInfo>& modules) {
	if (memory.isCrossBitness()) {
		if (listModulesFromPeb64(memory, modules)) {
			return true;
		}
		logger.log(ERROR_T, "Could not walk the 64-bit module list of the target.");
		return false;
	}
	return listModules(pid, modules);
}

bool findModuleIn(const std::vector<ModuleInfo>& modules, const std::string& name, ModuleInfo& module) {
	// The same DLL can be loaded twice from different paths, in that case the
	// first one wins and we say so
	const std::string wanted = fileNameOf(name);
	const ModuleInfo* found = nullptr;

	for (const ModuleInfo& candidate : modules) {
		const bool nameMatches = sameName(candidate.name, wanted);
		const bool pathMatches = sameName(candidate.path, name);
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
		return false;
	}

	module = *found;
	return true;
}

ThreadSuspender::~ThreadSuspender() {
	resume();
}

size_t ThreadSuspender::suspend(DWORD pid) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		logger.log(WARNING, "Could not list the threads to suspend: " + describeError(GetLastError()));
		return 0;
	}

	THREADENTRY32 entry{};
	entry.dwSize = sizeof(entry);

	if (Thread32First(snapshot, &entry)) {
		do {
			if (entry.th32OwnerProcessID != pid) {
				continue;
			}

			HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
			if (thread == nullptr) {
				continue;
			}
			if (SuspendThread(thread) == static_cast<DWORD>(-1)) {
				CloseHandle(thread);
				continue;
			}
			threads_.push_back(thread);
		} while (Thread32Next(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return threads_.size();
}

void ThreadSuspender::resume() {
	for (HANDLE thread : threads_) {
		ResumeThread(thread);
		CloseHandle(thread);
	}
	threads_.clear();
}
