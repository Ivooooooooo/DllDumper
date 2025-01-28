#include "Logger.h"
#include <iostream>

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
    std::cout << getLevelColor(level) << "[" << getLevelString(level) << "] " << message << "\033[0m" << std::endl;
}

Logger logger;
