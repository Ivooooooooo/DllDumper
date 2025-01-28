#include "Dumper.h"
#include <iostream>
#include <fstream>
#include <basetsd.h>
#include "Logger.h"

bool CopyDLL(HANDLE hProcess, LPCVOID baseAddress, SIZE_T dllSize, const char* outputFilePath) {
	std::ofstream outFile(outputFilePath, std::ios::binary);
	if (!outFile.is_open()) {
		logger.log(ERROR_T, "Error creating the output file: " + std::string(outputFilePath));
		return false;
	}

	char* buffer = new char[dllSize];
	SIZE_T bytesRead;
	if (!ReadProcessMemory(hProcess, baseAddress, buffer, dllSize, &bytesRead)) {
		logger.log(ERROR_T, "Error reading process memory.");
		delete[] buffer;
		return false;
	}

	outFile.write(buffer, bytesRead);
	delete[] buffer;
	outFile.close();

	return true;
}