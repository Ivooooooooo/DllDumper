#ifndef DUMPER_H
#define DUMPER_H

#include <cstdint>
#include <string>
#include <vector>
#include <Windows.h>

struct DumpTarget {
	DWORD pid = 0;
	std::string moduleName;
	std::string modulePath;
	uintptr_t base = 0;
	SIZE_T mappedSize = 0;
};

struct UnreadableRange {
	uintptr_t address = 0;
	SIZE_T size = 0;
};

struct DumpResult {
	SIZE_T imageSize = 0;
	bool sizeFromHeaders = false;
	bool headersFixed = false;
	std::vector<UnreadableRange> unreadable;
};

bool DumpModule(HANDLE process, const DumpTarget& target, const std::string& outputPath, DumpResult& result);

#endif // DUMPER_H
