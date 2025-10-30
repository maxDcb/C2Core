#pragma once

#include "ModuleCmd.hpp"

#include <string>
#include <vector>

class SshExec : public ModuleCmd
{
public:
    SshExec();
    ~SshExec();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg);

    int osCompatibility()
    {
        return OS_LINUX | OS_WINDOWS;
    }

    static constexpr int ErrorLibssh2Init = 1;
    static constexpr int ErrorSocketInit = 2;
    static constexpr int ErrorResolve = 3;
    static constexpr int ErrorConnect = 4;
    static constexpr int ErrorSessionInit = 5;
    static constexpr int ErrorHandshake = 6;
    static constexpr int ErrorAuthentication = 7;
    static constexpr int ErrorChannelOpen = 8;
    static constexpr int ErrorExecute = 9;

private:
    struct Parameters
    {
        std::string host;
        std::string port = "22";
        std::string username;
        std::string password;
        std::string command;
    };

    std::string packParameters(const Parameters& params) const;
    Parameters unpackParameters(const std::string& data) const;
    int executeSshCommand(const Parameters& params, std::string& result) const;
};

#ifdef _WIN32
extern "C" __declspec(dllexport) SshExec* SshExecConstructor();
#else
extern "C" __attribute__((visibility("default"))) SshExec* SshExecConstructor();
#endif
