#pragma once

#include "ModuleCmd.hpp"

#include <string>
#include <vector>

class TaskScheduler : public ModuleCmd
{
public:
    TaskScheduler();
    ~TaskScheduler();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg);

    int osCompatibility()
    {
        return OS_WINDOWS;
    }

private:
    struct Parameters
    {
        std::string server;
        std::string taskName;
        std::string command;
        std::string arguments;
        std::string username;
        std::string password;
        bool skipRun = false;
        bool deleteAfterRun = false;
    };

    std::string packParameters(const Parameters& params) const;
    Parameters unpackParameters(const std::string& data) const;

#ifdef _WIN32
    std::string executeTask(const Parameters& params) const;
#endif
};

#ifdef _WIN32
extern "C" __declspec(dllexport) TaskScheduler* TaskSchedulerConstructor();
#else
extern "C" __attribute__((visibility("default"))) TaskScheduler* TaskSchedulerConstructor();
#endif
