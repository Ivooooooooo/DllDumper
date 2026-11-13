#ifndef PROCESS_UTILS_H
#define PROCESS_UTILS_H

#include <string>
#include <vector>
#include <Windows.h>

#include "RemoteMemory.h"

struct ModuleInfo {
	std::string name;     // file name as the loader reports it
	std::string path;     // full path
	Address base = 0;
	SIZE_T mappedSize = 0;
};

enum class Bitness {
	Unknown,
	X86,
	X64,
	Arm64
};

// Suspends every thread of a process for as long as the object is alive, so the
// image does not move under us while it is being read
class ThreadSuspender {
public:
	ThreadSuspender() = default;
	~ThreadSuspender();

	ThreadSuspender(const ThreadSuspender&) = delete;
	ThreadSuspender& operator=(const ThreadSuspender&) = delete;

	size_t suspend(DWORD pid);
	void resume();
	size_t count() const { return threads_.size(); }

private:
	std::vector<HANDLE> threads_;
};

std::string describeError(DWORD code);
const char* bitnessName(Bitness bitness);
Bitness selfBitness();
Bitness processBitness(HANDLE process);
bool sameName(const std::string& first, const std::string& second);
bool enableDebugPrivilege();
bool findProcessByName(const std::string& exeName, DWORD& pid);

// Uses Toolhelp when both sides are the same bitness, and reads the 64-bit PEB
// through NtWow64QueryInformationProcess64 when a WOW64 build asks about a 64-bit
// target, which Toolhelp cannot do
bool listModulesForTarget(const RemoteMemory& memory, DWORD pid, std::vector<ModuleInfo>& modules);
bool findModuleIn(const std::vector<ModuleInfo>& modules, const std::string& name, ModuleInfo& module);

#endif // PROCESS_UTILS_H
