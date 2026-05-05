#pragma once

#include "ModuleCmd.hpp"

#ifdef _WIN32
    #include <Windows.h>
#endif

class Inject : public ModuleCmd
{

public:
    Inject();
    ~Inject();

    std::string getInfo();

    int initConfig(const nlohmann::json &config);
    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    int initPreparedShellcode(const ModulePreparedShellcodeTask& task, C2Message& c2Message) override;
#endif
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg) override;
    int osCompatibility() 
    {
        return OS_WINDOWS;
    }

private:
    std::string m_processToSpawn;
    bool m_useSyscall;

};


#ifdef _WIN32

extern "C" __declspec(dllexport) Inject * A_InjectConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Inject * InjectConstructor();

#endif
