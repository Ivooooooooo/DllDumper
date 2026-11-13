#include "Logger.h"

#include <iostream>
#include <Windows.h>

namespace {

bool g_stdOutIsConsole = false;
bool g_stdErrIsConsole = false;

bool enableAnsi(HANDLE handle) {
	DWORD mode = 0;
	if (handle == INVALID_HANDLE_VALUE || !GetConsoleMode(handle, &mode)) {
		return false;
	}
	return SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
}

// Colour codes only make sense on a real console, when the output is redirected
// to a file they end up as escape sequences in the middle of the text
void prepareConsole() {
	static bool prepared = false;
	if (prepared) {
		return;
	}
	prepared = true;

	g_stdOutIsConsole = enableAnsi(GetStdHandle(STD_OUTPUT_HANDLE));
	g_stdErrIsConsole = enableAnsi(GetStdHandle(STD_ERROR_HANDLE));
}

}

void Logger::log(LogLevel level, const std::string& message) {
	logToConsole(level, message);
}

std::string Logger::getLevelString(LogLevel level) {
	switch (level) {
	case INFO: return "INFO";
	case WARNING: return "WARNING";
	case ERROR_T: return "ERROR";
	default: return "UNKNOWN";
	}
}

std::string Logger::getLevelColor(LogLevel level) {
	switch (level) {
	case INFO: return "\033[1;32m"; // Green
	case WARNING: return "\033[1;33m"; // Yellow
	case ERROR_T: return "\033[1;31m"; // Red
	default: return "\033[0m"; // Reset
	}
}

void Logger::logToConsole(LogLevel level, const std::string& message) {
	prepareConsole();

	const bool useColor = (level == INFO) ? g_stdOutIsConsole : g_stdErrIsConsole;
	std::ostream& out = (level == INFO) ? std::cout : std::cerr;

	if (useColor) {
		out << getLevelColor(level);
	}
	out << "[" << getLevelString(level) << "] " << message;
	if (useColor) {
		out << "\033[0m";
	}
	out << std::endl;
}

Logger logger;
