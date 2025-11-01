#pragma once

#include "ModuleCmd.hpp"

#ifdef __linux__
#define LOGON32_LOGON_INTERACTIVE 2
#define LOGON32_LOGON_NETWORK     3
#define LOGON32_LOGON_BATCH       4
#define LOGON32_LOGON_SERVICE     5
#define LOGON32_LOGON_UNLOCK      7
#define LOGON32_LOGON_NETWORK_CLEARTEXT 8
#define LOGON32_LOGON_NEW_CREDENTIALS   9
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
