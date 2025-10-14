#pragma once

#include "ModuleCmd.hpp"


class ListProcesses : public ModuleCmd
{

public:
    ListProcesses();
    ~ListProcesses();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int osCompatibility() 
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
    std::string listProcesses();

};


#ifdef _WIN32

extern "C" __declspec(dllexport) ListProcesses * ListProcessesConstructor();

#else

extern "C"  __attribute__((visibility("default"))) ListProcesses * ListProcessesConstructor();

#endif