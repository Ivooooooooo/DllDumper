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

// Addresses are typed in hex, the 0x is optional
bool parseAddress(std::string value, uint64_t& address) {
	if (value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
		value = value.substr(2);
	}

	unsigned long long parsed = 0;
	const char* begin = value.data();
	const char* end = begin + value.size();

	auto result = std::from_chars(begin, end, parsed, 16);
	if (result.ec != std::errc() || result.ptr != end || parsed == 0) {
		return false;
	}

	address = parsed;
	return true;
}

// -output=x and -output x are both accepted, the second form is handy in a shell
std::string stripDashes(const std::string& name) {
	size_t start = name.find_first_not_of('-');
	return (start == std::string::npos) ? std::string() : name.substr(start);
}

bool optionTakesValue(const std::string& key) {
	return key == "pid" || key == "process" || key == "dllName" || key == "output"
		|| key == "base" || key == "layout";
}

}

void printUsage(const char* exeName) {
	std::cout
		<< "Usage: " << exeName << " -pid=<pid> -dllName=<module> [options]\n"
		<< "       " << exeName << " -pid=<pid> -base=<address> [options]\n"
		<< "       " << exeName << " -pid=<pid> -list [-scan]\n"
		<< "\n"
		<< "  -pid        process id to read from\n"
		<< "  -process    process name (notepad.exe), for when you don't have the pid\n"
		<< "  -dllName    module to dump, file name or full path\n"
		<< "  -base       dump whatever image sits at this address, in hex\n"
		<< "  -output     output file, defaults to Dump\\<module>_Dump.dll\n"
		<< "  -list       print the modules of the process and exit\n"
		<< "  -scan       also look for images that are not in the loader list\n"
		<< "  -layout     image or file, how the bytes are laid out in memory\n"
		<< "  -no-suspend do not freeze the target while the image is read\n"
		<< "  -h          this text\n"
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
		if (key == "scan") {
			options.scan = true;
			continue;
		}
		if (key == "no-suspend" || key == "nosuspend") {
			options.noSuspend = true;
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
		else if (key == "output") {
			options.output = value;
		}
		else if (key == "base") {
			if (!parseAddress(value, options.base)) {
				logger.log(ERROR_T, "Not a valid address: " + value);
				return false;
			}
		}
		else if (key == "layout") {
			if (value == "image") {
				options.layout = Layout::Image;
			}
			else if (value == "file") {
				options.layout = Layout::File;
			}
			else {
				logger.log(ERROR_T, "-layout takes image or file, not " + value);
				return false;
			}
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
	if (!options.list && options.dllName.empty() && options.base == 0) {
		logger.log(ERROR_T, "Need -dllName or -base unless you use -list.");
		return false;
	}

	return true;
}
