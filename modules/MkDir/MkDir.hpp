#pragma once

#include "ModuleCmd.hpp"

class MkDir : public ModuleCmd
{
public:
    MkDir();
    ~MkDir();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg);
    int osCompatibility()
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
};

#ifdef _WIN32
extern "C" __declspec(dllexport) MkDir * MkDirConstructor();
#else
extern "C"  __attribute__((visibility("default"))) MkDir * MkDirConstructor();
#endif

