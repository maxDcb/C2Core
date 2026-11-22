#include "ListDirectory.hpp"

#include <cstring>
#include <array>
#include <filesystem>
#include <sstream>

#include "Common.hpp"


using namespace std;

constexpr std::string_view moduleName = "ls";
constexpr unsigned long long moduleHash = djb2(moduleName);

namespace
{
    constexpr int ERROR_LIST_DIRECTORY = 1;
}


#ifdef _WIN32

__declspec(dllexport) ListDirectory* ListDirectoryConstructor() 
{
    return new ListDirectory();
}

#else

__attribute__((visibility("default"))) ListDirectory * ListDirectoryConstructor()
{
    return new ListDirectory();
}

#endif


ListDirectory::ListDirectory()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

ListDirectory::~ListDirectory()
{
}

std::string ListDirectory::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "ListDirectory Module:\n";
    info += "List the contents of a directory on the victim machine.\n";
    info += "Displays files and folders within the specified path. If no path is provided, lists the current working directory.\n";
    info += "\nExamples:\n";
    info += "- ls /tmp\n";
    info += "- ls C:\\Users\\Public\n";
#endif
    return info;
}

int ListDirectory::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
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

int ListDirectory::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    string path = c2Message.cmd();
    std::string outCmd = listDirectory(path);

    c2RetMessage.set_instruction(c2RetMessage.instruction());
    c2RetMessage.set_cmd(path);
    if (outCmd.find("Error:") == 0)
    {
        c2RetMessage.set_errorCode(ERROR_LIST_DIRECTORY);
    }
    else
        c2RetMessage.set_errorCode(0);
    c2RetMessage.set_returnvalue(outCmd);

    return 0;
}

int ListDirectory::errorCodeToMsg(const C2Message &c2RetMessage, std::string &errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    if (c2RetMessage.errorCode() == ERROR_LIST_DIRECTORY)
    {
        errorMsg = "Failed: Could not list directory";
        if (!c2RetMessage.returnvalue().empty())
            errorMsg += "\n" + c2RetMessage.returnvalue();
    }
#endif
    return 0;
}

struct HumanReadable {
    std::uintmax_t size{};
  private: friend
    std::ostream& operator<<(std::ostream& os, HumanReadable hr) {
        int i{};
        double mantissa = hr.size;
        for (; mantissa >= 1024.; mantissa /= 1024., ++i) { }
        mantissa = std::ceil(mantissa * 10.) / 10.;
        os << mantissa << "BKMGTPE"[i];
        return i == 0 ? os : os << "B (" << hr.size << ')';
    }
};

std::string perms(filesystem::perms p)
{
    std::string permission;
    permission += ((p & filesystem::perms::owner_read) != filesystem::perms::none ? "r" : "-");
    permission += ((p & filesystem::perms::owner_write) != filesystem::perms::none ? "w" : "-");
    permission += ((p & filesystem::perms::owner_exec) != filesystem::perms::none ? "x" : "-");
    permission += ((p & filesystem::perms::group_read) != filesystem::perms::none ? "r" : "-");
    permission += ((p & filesystem::perms::group_write) != filesystem::perms::none ? "w" : "-");
    permission += ((p & filesystem::perms::group_exec) != filesystem::perms::none ? "x" : "-");
    permission += ((p & filesystem::perms::others_read) != filesystem::perms::none ? "r" : "-");
    permission += ((p & filesystem::perms::others_write) != filesystem::perms::none ? "w" : "-");
    permission += ((p & filesystem::perms::others_exec) != filesystem::perms::none ? "x" : "-");

    return permission;
}

std::string ListDirectory::listDirectory(const std::string& path)
{
    std::string result;

    try
    {
        std::string actualPath=path;
        if(actualPath.empty())
            actualPath=std::filesystem::current_path().string();

        std::error_code e;
        if (!std::filesystem::is_directory(actualPath, e))
        {
            result += "Error: ";
            result += e ? e.message() : "path is not a directory";
            result += "\n";
            return result;
        }

        const filesystem::directory_iterator entries(actualPath, e);
        if (e)
        {
            result += "Error: ";
            result += e.message();
            result += "\n";
            return result;
        }

        result += actualPath;
        result += ":\n";

        for (const filesystem::directory_entry& file : entries)
        {
            try
            {
                filesystem::file_status status = filesystem::status(file.path().string(), e);
                result += " ";
                switch(status.type())
                {
                    case filesystem::file_type::none: result += "n"; break;
                    case filesystem::file_type::not_found: result += "n"; break;
                    case filesystem::file_type::regular: result += "f"; break;
                    case filesystem::file_type::directory: result += "d"; break;
                    case filesystem::file_type::symlink: result += "s"; break;
                    case filesystem::file_type::block: result += "b"; break;
                    case filesystem::file_type::character: result += "c"; break;
                    case filesystem::file_type::fifo: result += "f"; break;
                    case filesystem::file_type::socket: result += "s"; break;
                    case filesystem::file_type::unknown: result += "u"; break;
                    default: result += "-"; break;
                }

                result += " ";
                result += perms(status.permissions());
                result += " ";
            }
            catch (...)
            {
                result += "             ";
            }

            try
            {
                std::stringstream ss;
                ss << HumanReadable{file.file_size()};
                std::string mySize = ss.str();
                result += mySize;
                int sizeBlanc = std::max(0, int(20-(mySize.size())));
                result += std::string(sizeBlanc, ' ');
            }
            catch(filesystem::filesystem_error& e)
            {
                result += std::string(20, ' ');
            }

            result += " ";
            result += file.path().string();
            result += "\n";
        }
    }
    catch (const std::exception &exc)
    {
        result += "Error: ";
        result += exc.what();
        result += "\n";
    }

    return result;
}
