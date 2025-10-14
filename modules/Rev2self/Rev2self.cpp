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
    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd("");

    return 0;
}


int Rev2self::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    std::string out = rev2self();

    c2RetMessage.set_instruction(c2RetMessage.instruction());
    c2RetMessage.set_cmd("");
    c2RetMessage.set_returnvalue(out);

    return 0;
}


std::string Rev2self::rev2self()
{
    std::string result;

#ifdef __linux__ 

    result += "Rev2self don't work in linux.\n";

#elif _WIN32
    if(RevertToSelf())
        result += "Reverted to self.\n";
    else
        result += "Fail to revert to self.\n";
#endif

    return result;
}