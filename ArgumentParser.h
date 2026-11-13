#ifndef ARGUMENT_PARSER_H
#define ARGUMENT_PARSER_H

#include <string>
#include <Windows.h>

struct Options {
	DWORD pid = 0;
	std::string process;
	std::string dllName;
	std::string output;
	bool list = false;
	bool help = false;
};

void printUsage(const char* exeName);
bool parseArguments(int argc, char* argv[], Options& options);

#endif // ARGUMENT_PARSER_H
