#ifndef ARGUMENT_PARSER_H
#define ARGUMENT_PARSER_H

#include <string>
#include <Windows.h>

void parseArguments(int argc, char* argv[], DWORD& pid, std::string& dllName, std::string& outputFile);

#endif // ARGUMENT_PARSER_H