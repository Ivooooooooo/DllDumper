#ifndef DUMPER_H
#define DUMPER_H

#include <windows.h>
#include <string>

bool CopyDLL(HANDLE hProcess, LPCVOID baseAddress, SIZE_T dllSize, const char* outputFilePath);

#endif // DUMPER_H