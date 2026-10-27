#pragma once

#include "ModuleCmd.hpp"

class HostContext : public ModuleCmd
{
public:
    HostContext();
    std::string getInfo();
    int init(std::vector<std::string>& splitCommand, C2Message& message);
    int process(C2Message& message, C2Message& response);
    int osCompatibility() { return OS_LINUX; }

private:
    std::string collect() const;
};

#ifdef _WIN32
extern "C" __declspec(dllexport) HostContext* HostContextConstructor();
#else
extern "C" __attribute__((visibility("default"))) HostContext* HostContextConstructor();
#endif
