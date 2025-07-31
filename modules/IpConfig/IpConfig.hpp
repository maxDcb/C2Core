#pragma once

#include "ModuleCmd.hpp"

class IpConfig : public ModuleCmd
{
public:
    IpConfig();
    ~IpConfig();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int osCompatibility()
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
    std::string runIpconfig();
};

#ifdef _WIN32
extern "C" __declspec(dllexport) IpConfig* IpConfigConstructor();
#else
extern "C" __attribute__((visibility("default"))) IpConfig* IpConfigConstructor();
#endif
