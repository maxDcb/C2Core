#pragma once

#include "ModuleCmd.hpp"

class Remove : public ModuleCmd
{
public:
    Remove();
    ~Remove();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg);
    int osCompatibility() {return OS_LINUX | OS_WINDOWS;}
};

#ifdef _WIN32
extern "C" __declspec(dllexport) Remove * RemoveConstructor();
#else
extern "C"  __attribute__((visibility("default"))) Remove * RemoveConstructor();
#endif
