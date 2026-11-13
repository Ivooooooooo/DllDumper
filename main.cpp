#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "ArgumentParser.h"
#include "Dumper.h"
#include "Hex.h"
#include "Logger.h"
#include "ProcessUtils.h"

namespace fs = std::filesystem;

namespace {

constexpr int kExitOk = 0;
constexpr int kExitArguments = 1;
constexpr int kExitProcess = 2;
constexpr int kExitDump = 3;

fs::path buildOutputPath(const std::string& requested, const std::string& moduleName) {
	fs::path output;
	if (requested.empty()) {
		output = fs::path("Dump") / moduleName;
	}
	else {
		output = fs::path(requested);
		if (output.filename().empty()) {
			output /= moduleName;
		}
	}

	if (!output.has_extension()) {
		output += ".dll";
	}

	const std::string stem = output.stem().string();
	output.replace_filename(stem + "_Dump" + output.extension().string());

	if (output.parent_path().empty()) {
		output = fs::path("Dump") / output;
	}
	return output;
}

void printModules(DWORD pid, const std::vector<ModuleInfo>& modules) {
	std::cout << "Modules loaded in pid " << pid << ":" << std::endl;
	for (const ModuleInfo& module : modules) {
		std::cout << "  " << toHex(module.base, 16)
			<< "  " << toHex(module.mappedSize, 8)
			<< "  " << module.name
			<< "  " << module.path
			<< std::endl;
	}
}

}

int main(int argc, char* argv[]) {
	Options options;
	if (!parseArguments(argc, argv, options)) {
		return kExitArguments;
	}
	if (options.help) {
		printUsage(argv[0]);
		return kExitOk;
	}

	// Not fatal, if this fails OpenProcess is the one that will complain
	enableDebugPrivilege();

	DWORD pid = options.pid;
	if (pid == 0 && !findProcessByName(options.process, pid)) {
		logger.log(ERROR_T, "No running process is called " + options.process + ".");
		return kExitProcess;
	}

	if (options.list) {
		std::vector<ModuleInfo> modules;
		if (!listModules(pid, modules)) {
			return kExitProcess;
		}
		printModules(pid, modules);
		return kExitOk;
	}

	ModuleInfo module;
	if (!findModule(pid, options.dllName, module)) {
		return kExitProcess;
	}
	logger.log(INFO, "Found " + module.name + " at " + toHex(module.base) + ", size " + toHex(module.mappedSize) + ".");

	const fs::path output = buildOutputPath(options.output, module.name);
	if (!output.parent_path().empty()) {
		std::error_code error;
		fs::create_directories(output.parent_path(), error);
		if (error) {
			logger.log(ERROR_T, "Could not create " + output.parent_path().string() + ": " + error.message());
			return kExitDump;
		}
	}
	logger.log(INFO, "Writing " + output.string());

	HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (process == nullptr) {
		logger.log(ERROR_T, "OpenProcess failed: " + describeError(GetLastError()) + " Try running as administrator.");
		return kExitProcess;
	}

	DumpTarget target;
	target.pid = pid;
	target.moduleName = module.name;
	target.modulePath = module.path;
	target.base = module.base;
	target.mappedSize = module.mappedSize;

	DumpResult result;
	const bool dumped = DumpModule(process, target, output.string(), result);
	CloseHandle(process);

	if (!dumped) {
		return kExitDump;
	}

	logger.log(INFO, "Dumped " + toHex(result.imageSize) + (result.headersFixed
		? " with the section headers rebuilt for a flat layout."
		: "."));
	if (!result.unreadable.empty()) {
		logger.log(WARNING, std::to_string(result.unreadable.size()) + " range(s) could not be read and are zero filled, they are listed in the .json.");
	}
	logger.log(INFO, "Done.");
	return kExitOk;
}
