#include "PrintWorkingDirectory.hpp"

#include <cstring>
#include <array>
#include <filesystem>

using namespace std;


const std::string moduleName = "pwd";


#ifdef _WIN32

__declspec(dllexport) PrintWorkingDirectory* PrintWorkingDirectoryConstructor() 
{
    return new PrintWorkingDirectory();
}

#endif

PrintWorkingDirectory::PrintWorkingDirectory()
	: ModuleCmd(moduleName)
{
}

PrintWorkingDirectory::~PrintWorkingDirectory()
{
}

std::string PrintWorkingDirectory::getInfo()
{
	std::string info;
	info += "pwd:\n";
	info += "PrintWorkingDirectory\n";
	info += "exemple:\n";
	info += "- pwd\n";

	return info;
}

int PrintWorkingDirectory::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
	c2Message.set_instruction(splitedCmd[0]);
	c2Message.set_cmd("");

	return 0;
}


int PrintWorkingDirectory::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	std::string outCmd = printWorkingDirectory();

	c2RetMessage.set_instruction(m_name);
	c2RetMessage.set_cmd("");
	c2RetMessage.set_returnvalue(outCmd);

	return 0;
}


std::string PrintWorkingDirectory::printWorkingDirectory()
{
	std::string result;
    result = filesystem::current_path().string();

	return result;
}