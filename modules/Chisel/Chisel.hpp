#pragma once

#include "ModuleCmd.hpp"


class Chisel : public ModuleCmd
{

public:
    Chisel();
    ~Chisel();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    int initPreparedShellcode(const ModulePreparedShellcodeTask& task, C2Message& c2Message) override;
#endif
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int followUp(const C2Message &c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg) override;
    int osCompatibility() 
    {
        return OS_WINDOWS;
    }

private:
    std::vector<std::pair<int, std::string>> m_instances;

};


#ifdef _WIN32

extern "C" __declspec(dllexport) Chisel * A_ChiselConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Chisel * ChiselConstructor();

#endif
