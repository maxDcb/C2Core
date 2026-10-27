#pragma once

#include "ModuleCmd.hpp"

class HostContext : public ModuleCmd
{
public:
    HostContext();
    ~HostContext();
    std::string getInfo() override;
    int init(std::vector<std::string>& splitCommand, C2Message& message) override;
    int process(C2Message& message, C2Message& response) override;
    int errorCodeToMsg(const C2Message& response, std::string& errorMsg) override;
    int osCompatibility() override { return OS_LINUX | OS_WINDOWS; }

private:
    std::string collect(int& errorCode) const;
};

#ifdef _WIN32
extern "C" __declspec(dllexport) HostContext* HostContextConstructor();
#else
extern "C" __attribute__((visibility("default"))) HostContext* HostContextConstructor();
#endif
