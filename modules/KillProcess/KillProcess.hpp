#pragma once

#include "ModuleCmd.hpp"

class KillProcess : public ModuleCmd
{
public:
    KillProcess();
    ~KillProcess();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg);
    int osCompatibility() {return OS_LINUX | OS_WINDOWS;}
};

#ifdef _WIN32
extern "C" __declspec(dllexport) KillProcess * KillProcessConstructor();
#else
extern "C"  __attribute__((visibility("default"))) KillProcess * KillProcessConstructor();
#endif
