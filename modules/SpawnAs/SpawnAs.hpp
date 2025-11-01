#pragma once

#include "ModuleCmd.hpp"


class SpawnAs : public ModuleCmd
{

public:
    SpawnAs();
    ~SpawnAs();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int osCompatibility()
    {
        return OS_WINDOWS;
    }

    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg) override;

private:

    struct Options
    {
        int logonType = 2;       // LOGON32_LOGON_INTERACTIVE 
        bool loadProfile = true;
        bool showWindow = false;
    };

    std::string packParameters(const Options& options) const;
    Options unpackParameters(const std::string& data) const;

};


#ifdef _WIN32

extern "C" __declspec(dllexport) SpawnAs * A_SpawnAsConstructor();

#else

extern "C"  __attribute__((visibility("default"))) SpawnAs * SpawnAsConstructor();

#endif
