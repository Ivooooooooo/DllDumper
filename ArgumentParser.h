#ifndef ARGUMENT_PARSER_H
#define ARGUMENT_PARSER_H

#include <cstdint>
#include <string>
#include <Windows.h>

enum class Layout {
	Auto,
	Image,
	File
};

struct Options {
	DWORD pid = 0;
	std::string process;
	std::string dllName;
	std::string output;
	uint64_t base = 0;
	Layout layout = Layout::Auto;
	bool list = false;
	bool scan = false;
	bool noSuspend = false;
	bool help = false;
};

void printUsage(const char* exeName);
bool parseArguments(int argc, char* argv[], Options& options);

#endif // ARGUMENT_PARSER_H
