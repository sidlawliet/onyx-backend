#pragma once

#include <iostream>
#include <sstream>
#include <string>
#include <mutex>
#include <chrono>
#include <iomanip>

namespace onyx::utils {

enum class LogLevel {
    DEBUG_LEVEL,
    INFO_LEVEL,
    WARN_LEVEL,
    ERROR_LEVEL
};

class Logger {
public:
    static Logger& instance() {
        static Logger logger;
        return logger;
    }

    void log(LogLevel level, const std::string& message) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);

        std::stringstream ss;
        ss << "[" << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%d %H:%M:%S") << "] ";

        switch (level) {
            case LogLevel::DEBUG_LEVEL:
                ss << "\033[36m[DEBUG]\033[0m ";
                break;
            case LogLevel::INFO_LEVEL:
                ss << "\033[32m[INFO]\033[0m  ";
                break;
            case LogLevel::WARN_LEVEL:
                ss << "\033[33m[WARN]\033[0m  ";
                break;
            case LogLevel::ERROR_LEVEL:
                ss << "\033[31m[ERROR]\033[0m ";
                break;
        }

        ss << message << std::endl;
        std::cout << ss.str();
        std::cout.flush();
    }

    static void info(const std::string& msg) { instance().log(LogLevel::INFO_LEVEL, msg); }
    static void warn(const std::string& msg) { instance().log(LogLevel::WARN_LEVEL, msg); }
    static void error(const std::string& msg) { instance().log(LogLevel::ERROR_LEVEL, msg); }
    static void debug(const std::string& msg) { instance().log(LogLevel::DEBUG_LEVEL, msg); }

private:
    Logger() = default;
    std::mutex mutex_;
};

} // namespace onyx::utils
