#ifndef DUMPER_H
#define DUMPER_H

#include <cstdint>
#include <string>
#include <vector>
#include <Windows.h>

#include "RemoteMemory.h"

struct DumpTarget {
	DWORD pid = 0;
	std::string moduleName;
	std::string modulePath;
	Address base = 0;
	Address fallbackSize = 0;  // only used when the header cannot be read
	bool imageLayout = true;   // sections sit at their VirtualAddress
};

struct UnreadableRange {
	Address address = 0;
	Address size = 0;
};

struct DumpResult {
	Address imageSize = 0;
	bool sizeFromHeaders = false;
	bool headersFixed = false;
	bool managed = false;
	std::vector<UnreadableRange> unreadable;
};

bool DumpModule(const RemoteMemory& memory, const DumpTarget& target, const std::string& outputPath, DumpResult& result);

#endif // DUMPER_H
