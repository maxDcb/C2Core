#include "Rev2self.hpp"

#include <cstring>

#ifdef __linux__

#elif _WIN32
#include <windows.h>
#endif

#include "Common.hpp"


using namespace std;

constexpr std::string_view moduleName = "rev2self";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) Rev2self* Rev2selfConstructor() 
{
    return new Rev2self();
}

#else

__attribute__((visibility("default"))) Rev2self* Rev2selfConstructor() 
{
    return new Rev2self();
}

#endif

Rev2self::Rev2self()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

Rev2self::~Rev2self()
{
}

std::string Rev2self::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "rev2self:\n";
    info += "Drop the impersonation of a token, created with makeToken\n";
    info += "exemple:\n";
    info += "- rev2self\n";
#endif
    return info;
}

int Rev2self::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (splitedCmd.size() != 1)
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }
    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd("");
#endif

    return 0;
}


int Rev2self::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd("");
    c2RetMessage.set_returnvalue("");
#ifdef _WIN32
    if (!RevertToSelf())
    {
        c2RetMessage.set_errorCode(1);
        return 0;
    }
    c2RetMessage.set_errorCode(0);
    c2RetMessage.set_returnvalue("Reverted to self.\n");
#else
    c2RetMessage.set_errorCode(2);
#endif
    return 0;
}

int Rev2self::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    switch (c2RetMessage.errorCode())
    {
    case 0: errorMsg.clear(); break;
    case 1: errorMsg = "Failed to revert to the original token."; break;
    case 2: errorMsg = "Rev2self is only supported on Windows."; break;
    default: errorMsg = "Rev2self failed with an unknown error."; break;
    }
#endif
    return 0;
}
