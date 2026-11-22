#pragma once

#include "ModuleCmd.hpp"


class Tree : public ModuleCmd
{

public:
    Tree();
    ~Tree();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg) override;
    int osCompatibility() 
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
    bool iterProcess(const std::string& path, int depth, std::string& result);

};


#ifdef _WIN32

extern "C" __declspec(dllexport) Tree * TreeConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Tree * TreeConstructor();

#endif
