#ifndef LOGGER_H
#define LOGGER_H

#include <string>

enum LogLevel {
    INFO,
    WARNING,
    ERROR_T
};

class Logger {
public:
    Logger() = default;
    ~Logger() = default;

    void log(LogLevel level, const std::string& message);

private:
    std::string getLevelString(LogLevel level);
    std::string getLevelColor(LogLevel level);
    void logToConsole(LogLevel level, const std::string& message);
};

extern Logger logger;

#endif // LOGGER_H
