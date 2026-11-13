#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "ArgumentParser.h"
#include "Dumper.h"
#include "Hex.h"
#include "Logger.h"
#include "ProcessUtils.h"
#include "RemoteMemory.h"
#include "Scanner.h"

namespace fs = std::filesystem;

namespace {

constexpr int kExitOk = 0;
constexpr int kExitArguments = 1;
constexpr int kExitProcess = 2;
constexpr int kExitDump = 3;

// NtWow64QueryVirtualMemory64 refuses a handle that only has the limited query
// right, but asking for the full one fails on processes that only grant the limited
HANDLE openProcessForRead(DWORD pid) {
	HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (process == nullptr) {
		process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	}
	return process;
}

struct Target {
	std::string name;
	std::string path;
	Address base = 0;
	Address size = 0;
	bool imageLayout = true;
	bool managed = false;
	bool manual = false;
};

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

std::string joinNames(const std::vector<std::string>& names) {
	std::string joined;
	for (const std::string& name : names) {
		if (!joined.empty()) {
			joined += ", ";
		}
		joined += name;
	}
	return joined;
}

void printModules(DWORD pid, const std::vector<ModuleInfo>& modules, const std::vector<ScannedImage>& manual) {
	std::cout << "Modules in pid " << pid << ":" << std::endl;
	for (const ModuleInfo& module : modules) {
		std::cout << "  " << toHex(module.base, 16)
			<< "  " << toHex(module.mappedSize, 8)
			<< "  " << module.name
			<< "  " << module.path
			<< std::endl;
	}

	for (const ScannedImage& image : manual) {
		std::cout << "  " << toHex(image.base, 16)
			<< "  " << toHex(image.size, 8)
			<< "  " << (image.name.empty() ? std::string("<no exports>") : image.name)
			<< "  [not in the loader list" << (image.managed ? ", .NET" : "") << "]"
			<< std::endl;
	}
}

bool resolveTarget(const RemoteMemory& memory, const std::vector<ModuleInfo>& modules, const Options& options, Target& target) {
	if (options.base != 0) {
		ScannedImage image;
		if (!describeImage(memory, options.base, image)) {
			logger.log(ERROR_T, "There is no PE image at " + toHex(options.base) + ".");
			return false;
		}

		target.name = image.name.empty() ? "image_" + toHex(image.base) : image.name;
		target.base = image.base;
		target.size = image.size;
		target.imageLayout = image.imageLayout;
		target.managed = image.managed;
		target.manual = true;
		return true;
	}

	ModuleInfo module;
	if (findModuleIn(modules, options.dllName, module)) {
		target.name = module.name;
		target.path = module.path;
		target.base = module.base;
		target.size = module.mappedSize;
		target.imageLayout = true;

		// Only interesting for the .NET flag, the loader already told us the rest
		ScannedImage described;
		if (describeImage(memory, module.base, described)) {
			target.managed = described.managed;
		}
		return true;
	}

	if (memory.isCrossBitness()) {
		logger.log(ERROR_T, options.dllName + " is not in the module list, and this 32-bit build cannot walk"
			" a 64-bit address space to look for it. Use -base with the address.");
		return false;
	}

	logger.log(INFO, options.dllName + " is not in the loader list, scanning memory for it.");
	std::vector<ScannedImage> images;
	if (!scanForImages(memory, images)) {
		return false;
	}

	std::vector<std::string> names;
	for (const ScannedImage& image : images) {
		if (image.name.empty()) {
			continue;
		}
		if (sameName(image.name, options.dllName)) {
			target.name = image.name;
			target.base = image.base;
			target.size = image.size;
			target.imageLayout = image.imageLayout;
			target.managed = image.managed;
			target.manual = true;
			return true;
		}
		names.push_back(image.name);
	}

	logger.log(ERROR_T, "Could not find " + options.dllName + " anywhere in the process.");
	if (!names.empty()) {
		logger.log(ERROR_T, "The images I did find are: " + joinNames(names));
	}
	else {
		logger.log(ERROR_T, "No PE images at all outside the loader list. If you know the address, use -base.");
	}
	return false;
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

	HANDLE process = openProcessForRead(pid);
	if (process == nullptr) {
		logger.log(ERROR_T, "OpenProcess failed for pid " + std::to_string(pid) + ": " + describeError(GetLastError()) + " Try running as administrator.");
		return kExitProcess;
	}

	const Bitness targetBitness = processBitness(process);
	const bool targetIs64Bit = targetBitness == Bitness::X64 || targetBitness == Bitness::Arm64
		|| (targetBitness == Bitness::Unknown && sizeof(void*) == 8);

	RemoteMemory memory(process, targetIs64Bit);

	if constexpr (sizeof(void*) == 4) {
		if (targetIs64Bit) {
			logger.log(WARNING, "This is the 32-bit build and the target is 64-bit. The module list comes from the"
				" 64-bit PEB, -base reads through NtWow64, but -scan cannot walk that address space.");
		}
	}

	std::vector<ModuleInfo> modules;
	const bool haveModules = listModulesForTarget(memory, pid, modules);

	if (options.list) {
		std::vector<ScannedImage> manual;

		if (options.scan) {
			if (memory.isCrossBitness()) {
				logger.log(ERROR_T, "A 32-bit build cannot scan a 64-bit address space, use -base for the address you want.");
			}
			else {
				std::vector<ScannedImage> images;
				if (scanForImages(memory, images)) {
					for (const ScannedImage& image : images) {
						// Listing every PE file that happens to sit in a heap buffer
						// buries the interesting ones
						if (!image.mapped && !image.managed) {
							continue;
						}

						bool known = false;
						for (const ModuleInfo& module : modules) {
							if (module.base == image.base) {
								known = true;
								break;
							}
						}
						if (!known) {
							manual.push_back(image);
						}
					}
				}
			}
		}

		if (!haveModules && manual.empty()) {
			CloseHandle(process);
			return kExitProcess;
		}

		printModules(pid, modules, manual);
		CloseHandle(process);
		return kExitOk;
	}

	Target target;
	if (!resolveTarget(memory, modules, options, target)) {
		CloseHandle(process);
		return kExitProcess;
	}

	if (options.layout == Layout::Image) {
		target.imageLayout = true;
	}
	else if (options.layout == Layout::File) {
		target.imageLayout = false;
	}

	logger.log(INFO, "Found " + target.name + " at " + toHex(target.base) + ", size " + toHex(target.size)
		+ (target.manual ? " (not in the loader list)" : "") + ".");

	const fs::path output = buildOutputPath(options.output, target.name);
	if (!output.parent_path().empty()) {
		std::error_code error;
		fs::create_directories(output.parent_path(), error);
		if (error) {
			logger.log(ERROR_T, "Could not create " + output.parent_path().string() + ": " + error.message());
			CloseHandle(process);
			return kExitDump;
		}
	}
	logger.log(INFO, "Writing " + output.string());

	// Freezing the target keeps the image from changing while it is being copied,
	// at the price of the process hanging for a moment
	ThreadSuspender suspender;
	if (!options.noSuspend) {
		const size_t suspended = suspender.suspend(pid);
		if (suspended > 0) {
			logger.log(INFO, "Suspended " + std::to_string(suspended) + " thread(s).");
		}
	}

	DumpTarget dumpTarget;
	dumpTarget.pid = pid;
	dumpTarget.moduleName = target.name;
	dumpTarget.modulePath = target.path;
	dumpTarget.base = target.base;
	dumpTarget.fallbackSize = target.size;
	dumpTarget.imageLayout = target.imageLayout;

	DumpResult result;
	const bool dumped = DumpModule(memory, dumpTarget, output.string(), result);
	suspender.resume();
	CloseHandle(process);

	if (!dumped) {
		return kExitDump;
	}

	if (result.managed) {
		logger.log(INFO, "Managed assembly, the metadata and the IL are in the dump as they were in memory.");
	}
	if (!target.imageLayout) {
		logger.log(INFO, "The bytes were already laid out as a file, they are copied as they are.");
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
