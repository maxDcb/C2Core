#pragma once

#include "ModuleCmd.hpp"

#include <string>
#include <vector>

class EnumerateRdpSessions : public ModuleCmd
{
public:
    struct Parameters
    {
        std::string server;
    };

    static constexpr int ERROR_WINDOWS_ONLY = 1;
    static constexpr int ERROR_OPEN_SERVER = 2;
    static constexpr int ERROR_ENUMERATE_SESSIONS = 3;

    EnumerateRdpSessions();
    ~EnumerateRdpSessions();

    std::string getInfo() override;

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message) override;
    int process(C2Message& c2Message, C2Message& c2RetMessage) override;
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg) override;
    int followUp(const C2Message& c2RetMessage) override;
    int osCompatibility() override
    {
        return OS_WINDOWS;
    }

private:
    std::string packParameters(const Parameters& params) const;
    Parameters unpackParameters(const std::string& data) const;
};

#ifdef _WIN32
extern "C" __declspec(dllexport) EnumerateRdpSessions* EnumerateRdpSessionsConstructor();
#else
extern "C" __attribute__((visibility("default"))) EnumerateRdpSessions* EnumerateRdpSessionsConstructor();
#endif
