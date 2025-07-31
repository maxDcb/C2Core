#pragma once

#include "ModuleCmd.hpp"

class Netstat : public ModuleCmd
{
public:
    Netstat();
    ~Netstat();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int osCompatibility()
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
    std::string runNetstat();
};

#ifdef _WIN32
extern "C" __declspec(dllexport) Netstat* NetstatConstructor();
#else
extern "C" __attribute__((visibility("default"))) Netstat* NetstatConstructor();
#endif
