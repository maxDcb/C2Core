#pragma once

#include "ModuleCmd.hpp"


class WmiExec : public ModuleCmd
{

public:
    WmiExec();
    ~WmiExec();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg);
    int osCompatibility() 
    {
        return OS_WINDOWS;
    }

private:
#ifdef _WIN32
    int execute(C2Message &c2Message, std::string& result) const;
#endif

};


#ifdef _WIN32

extern "C" __declspec(dllexport) WmiExec * WmiExecConstructor();

#else

extern "C"  __attribute__((visibility("default"))) WmiExec * WmiExecConstructor();

#endif
