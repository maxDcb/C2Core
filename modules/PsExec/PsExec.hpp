#pragma once

#include "ModuleCmd.hpp"


class PsExec : public ModuleCmd
{

public:
    PsExec();
    ~PsExec();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg);
    int osCompatibility() 
    {
        return OS_WINDOWS;
    }

private:

};


#ifdef _WIN32

extern "C" __declspec(dllexport) PsExec * PsExecConstructor();

#else

extern "C"  __attribute__((visibility("default"))) PsExec * PsExecConstructor();

#endif

