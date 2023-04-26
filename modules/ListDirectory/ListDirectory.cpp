#include "ListDirectory.hpp"

#include <cstring>
#include <array>
#include <filesystem>
#include <sstream>

using namespace std;


const std::string moduleName = "ls";


#ifdef _WIN32

__declspec(dllexport) ListDirectory* ListDirectoryConstructor() 
{
    return new ListDirectory();
}

#endif

ListDirectory::ListDirectory()
	: ModuleCmd(moduleName)
{
}

ListDirectory::~ListDirectory()
{
}

std::string ListDirectory::getInfo()
{
	std::string info;
	info += "ls:\n";
	info += "ListDirectory\n";
	info += "exemple:\n";
	info += "- ls /tmp\n";

	return info;
}

int ListDirectory::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
    string path;
    for (int idx = 1; idx < splitedCmd.size(); idx++) 
    {
        if(!path.empty())
            path+=" ";
        path+=splitedCmd[idx];
    }

	c2Message.set_instruction(splitedCmd[0]);
	c2Message.set_cmd(path);

	return 0;
}

int ListDirectory::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	string path = c2Message.cmd();
	std::string outCmd = listDirectory(path);

	c2RetMessage.set_instruction(m_name);
	c2RetMessage.set_cmd(path);
	c2RetMessage.set_returnvalue(outCmd);

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

        result += path;
        result += ":\n";

        std::error_code e;
        for (const filesystem::directory_entry& file : filesystem::directory_iterator(actualPath, e))
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