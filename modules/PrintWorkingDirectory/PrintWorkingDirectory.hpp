#pragma once

#include "ModuleCmd.hpp"


class PrintWorkingDirectory : public ModuleCmd
{

public:
    PrintWorkingDirectory();
    ~PrintWorkingDirectory();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg) override;
    int osCompatibility() 
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
    bool printWorkingDirectory(std::string& result);

};


#ifdef _WIN32

extern "C" __declspec(dllexport) PrintWorkingDirectory * PrintWorkingDirectoryConstructor();

#else

extern "C"  __attribute__((visibility("default"))) PrintWorkingDirectory * PrintWorkingDirectoryConstructor();

#endif
