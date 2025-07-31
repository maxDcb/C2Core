#pragma once

#include "ModuleCmd.hpp"

class EnumerateShares : public ModuleCmd
{
public:
    EnumerateShares();
    ~EnumerateShares();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int osCompatibility()
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
    std::string runEnum(const std::string& host);
};

#ifdef _WIN32
extern "C" __declspec(dllexport) EnumerateShares* EnumerateSharesConstructor();
#else
extern "C" __attribute__((visibility("default"))) EnumerateShares* EnumerateSharesConstructor();
#endif
