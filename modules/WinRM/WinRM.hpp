#pragma once

#include "ModuleCmd.hpp"

#include <string>
#include <vector>

class WinRM : public ModuleCmd
{
public:
    WinRM();
    ~WinRM();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg);

    int osCompatibility()
    {
        return OS_WINDOWS;
    }

    struct Parameters
    {
        std::string endpoint;
        std::string command;
        std::string arguments;
        std::string username;
        std::string password;
        bool useHttps = false;
    };
private:
    

    std::string packParameters(const Parameters& params) const;
    Parameters unpackParameters(const std::string& data) const;

#ifdef _WIN32
    std::string runCommand(const Parameters& params) const;
#endif
};

#ifdef _WIN32
extern "C" __declspec(dllexport) WinRM* WinRMConstructor();
#else
extern "C" __attribute__((visibility("default"))) WinRM* WinRMConstructor();
#endif
