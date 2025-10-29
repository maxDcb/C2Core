#pragma once

#include "ModuleCmd.hpp"

#include <string>
#include <vector>

class CimExec : public ModuleCmd
{
public:
    CimExec();
    ~CimExec();

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
        std::string hostname;
        std::string namespaceName;
        std::string command;
        std::string arguments;
        std::string username;
        std::string password;
    };

    std::string packParameters(const Parameters& params) const;
    Parameters unpackParameters(const std::string& data) const;

#ifdef _WIN32
    int invoke(const Parameters& params, std::string& result) const;
#endif
};

#ifdef _WIN32
extern "C" __declspec(dllexport) CimExec* CimExecConstructor();
#else
extern "C" __attribute__((visibility("default"))) CimExec* CimExecConstructor();
#endif
