#include "ArgumentParser.h"

#include <charconv>
#include <iostream>

#include "Logger.h"

namespace {

bool parsePid(const std::string& value, DWORD& pid) {
	unsigned long long parsed = 0;
	const char* begin = value.data();
	const char* end = begin + value.size();

	auto result = std::from_chars(begin, end, parsed);
	if (result.ec != std::errc() || result.ptr != end) {
		return false;
	}
	if (parsed == 0 || parsed > 0xFFFFFFFFull) {
		return false;
	}

	pid = static_cast<DWORD>(parsed);
	return true;
}

// -output=x and -output x are both accepted, the second form is handy in a shell
std::string stripDashes(const std::string& name) {
	size_t start = name.find_first_not_of('-');
	return (start == std::string::npos) ? std::string() : name.substr(start);
}

bool optionTakesValue(const std::string& key) {
	return key == "pid" || key == "process" || key == "dllName" || key == "output";
}

}

void printUsage(const char* exeName) {
	std::cout
		<< "Usage: " << exeName << " -pid=<pid> -dllName=<module> [-output=<file>]\n"
		<< "       " << exeName << " -process=<exe> -dllName=<module> [-output=<file>]\n"
		<< "       " << exeName << " -pid=<pid> -list\n"
		<< "\n"
		<< "  -pid      process id to read from\n"
		<< "  -process  process name (notepad.exe), for when you don't have the pid\n"
		<< "  -dllName  module to dump, file name or full path\n"
		<< "  -output   output file, defaults to Dump\\<module>_Dump.dll\n"
		<< "  -list     print the modules loaded in the process and exit\n"
		<< "  -h        this text\n"
		<< "\n"
		<< "Exit codes: 0 ok, 1 bad arguments, 2 process or module not found, 3 dump failed.\n";
}

bool parseArguments(int argc, char* argv[], Options& options) {
	for (int i = 1; i < argc; ++i) {
		const std::string arg = argv[i];
		if (arg.empty()) {
			continue;
		}

		std::string name = arg;
		std::string value;
		bool hasValue = false;

		size_t equals = arg.find('=');
		if (equals != std::string::npos) {
			name = arg.substr(0, equals);
			value = arg.substr(equals + 1);
			hasValue = true;
		}

		const std::string key = stripDashes(name);

		if (key == "h" || key == "help") {
			options.help = true;
			continue;
		}
		if (key == "list") {
			options.list = true;
			continue;
		}
		if (!optionTakesValue(key)) {
			logger.log(WARNING, "Ignoring unknown argument: " + arg);
			continue;
		}

		if (!hasValue) {
			if (i + 1 >= argc) {
				logger.log(ERROR_T, "Missing value for " + arg);
				return false;
			}
			value = argv[++i];
		}
		if (value.empty()) {
			logger.log(ERROR_T, "Empty value for -" + key);
			return false;
		}

		if (key == "pid") {
			if (!parsePid(value, options.pid)) {
				logger.log(ERROR_T, "Not a valid pid: " + value);
				return false;
			}
		}
		else if (key == "process") {
			options.process = value;
		}
		else if (key == "dllName") {
			options.dllName = value;
		}
		else {
			options.output = value;
		}
	}

	if (options.help) {
		return true;
	}

	if (options.pid == 0 && options.process.empty()) {
		logger.log(ERROR_T, "Need either -pid or -process.");
		return false;
	}
	if (options.pid != 0 && !options.process.empty()) {
		logger.log(ERROR_T, "-pid and -process are mutually exclusive.");
		return false;
	}
	if (!options.list && options.dllName.empty()) {
		logger.log(ERROR_T, "-dllName is required unless you use -list.");
		return false;
	}

	return true;
}
