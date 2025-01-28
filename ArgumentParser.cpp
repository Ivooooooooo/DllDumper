#include "ArgumentParser.h"
#include <iostream>
#include "Logger.h"

void parseArguments(int argc, char* argv[], DWORD& pid, std::string& dllName, std::string& outputFile) {
	for (int i = 1; i < argc; ++i) {
		std::string arg = argv[i];
		if (arg.find("-pid=") == 0) {
			pid = std::stoul(arg.substr(5));
		}
		else if (arg.find("-dllName=") == 0) {
			dllName = arg.substr(9);
		}
		else if (arg.find("-output=") == 0) {
			outputFile = arg.substr(8);
		}
		else {
			logger.log(WARNING, "Unknown argument: " + arg);
		}
	}
}