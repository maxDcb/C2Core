#pragma once

#include "ModuleCmd.hpp"


class Rev2self : public ModuleCmd
{

public:
    Rev2self();
    ~Rev2self();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg);
    int osCompatibility() 
    {
        return OS_WINDOWS;
    }

};


#ifdef _WIN32

extern "C" __declspec(dllexport) Rev2self * Rev2selfConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Rev2self * Rev2selfConstructor();

#endif