#include <iostream>
#include <string>
#include <direct.h>

#include "Dumper.h"
#include "ProcessUtils.h"
#include "Logger.h"
#include "ArgumentParser.h"

std::string formatOutputFileName(const std::string& output) {
	std::string outputFile = output;
	if (outputFile.find('.') == std::string::npos) {
		outputFile += ".dll";
	}
	size_t extPos = outputFile.find_last_of('.');
	outputFile.insert(extPos, "_Dump");
	return outputFile;
}

std::string getOutputDirectory(const std::string& output) {
	std::string outputDirectory;
	size_t pos = output.find_last_of("\\/");
	if (pos == std::string::npos) {
		outputDirectory = "Dump";
	}
	else {
		outputDirectory = output.substr(0, pos);
	}
	return outputDirectory;
}

std::string getOutputFilePath(const std::string& output, const std::string& directory) {
	size_t pos = output.find_last_of("\\/");
	std::string fileName = (pos == std::string::npos) ? output : output.substr(pos + 1);
	return directory + "\\" + fileName;
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		logger.log(ERROR_T, "Usage: " + std::string(argv[0]) + " -pid=<PID> -dllName=<DLL Name> -output=<Output File>");
		return 1;
	}

	DWORD pid = 0;
	std::string dllName;
	std::string outputFile;

	parseArguments(argc, argv, pid, dllName, outputFile);
	outputFile = formatOutputFileName(outputFile);

	std::string outputDirectory = getOutputDirectory(outputFile);
	char currentDir[MAX_PATH];
	GetModuleFileNameA(NULL, currentDir, MAX_PATH);
	std::string currentDirStr = currentDir;
	currentDirStr = currentDirStr.substr(0, currentDirStr.find_last_of("\\/"));

	std::string fullOutputDirectory = currentDirStr + "\\" + outputDirectory;
	std::string fullOutputPath = getOutputFilePath(outputFile, fullOutputDirectory);

	logger.log(INFO, "Output directory: " + fullOutputDirectory);

	if (_mkdir(fullOutputDirectory.c_str()) == -1 && errno != EEXIST) {
		char errorBuffer[256];
		strerror_s(errorBuffer, sizeof(errorBuffer), errno);
		logger.log(ERROR_T, "Failed to create output directory: " + fullOutputDirectory + ". Error: " + std::string(errorBuffer));
		return 1;
	}

	std::string foundDllPath;
	SIZE_T dllSize = 0;
	LPCVOID baseAddress = nullptr;
	if (getModuleNameFromPID(pid, dllName, foundDllPath, dllSize, baseAddress)) {
		logger.log(INFO, "Found DLL Path: " + foundDllPath);
		HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (hProcess == NULL) {
			logger.log(ERROR_T, "Failed to open the process.");
			return 1;
		}
		if (CopyDLL(hProcess, baseAddress, dllSize, fullOutputPath.c_str())) {
			logger.log(INFO, "DLL dump completed successfully.");
		}
		else {
			logger.log(ERROR_T, "Failed to dump the DLL.");
		}
		CloseHandle(hProcess);
	}
	else {
		logger.log(ERROR_T, "DLL not found in the process.");
	}

	return 0;
}