#pragma once

#include "ModuleCmd.hpp"

class Shell : public ModuleCmd
{
public:
    Shell();
    ~Shell();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int followUp(const C2Message &c2RetMessage);
    int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg);
    int osCompatibility()
    {
        return OS_LINUX;
    }

private:
    int startShell();
    void stopShell();

    int m_masterFd;

#ifdef _WIN32
    int m_pid;
#else
    pid_t m_pid;
#endif
    std::string m_program;
    bool m_started;
};

#ifdef _WIN32
extern "C" __declspec(dllexport) Shell * ShellConstructor();
#else
extern "C" __attribute__((visibility("default"))) Shell * ShellConstructor();
#endif
