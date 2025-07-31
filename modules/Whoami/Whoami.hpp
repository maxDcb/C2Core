#pragma once

#include "ModuleCmd.hpp"

class Whoami : public ModuleCmd
{
public:
    Whoami();
    ~Whoami();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int osCompatibility()
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
    std::string getInfoString();
};

#ifdef _WIN32
extern "C" __declspec(dllexport) Whoami* WhoamiConstructor();
#else
extern "C" __attribute__((visibility("default"))) Whoami* WhoamiConstructor();
#endif
