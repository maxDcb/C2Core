#include "PrintWorkingDirectory.hpp"

#include <cstring>
#include <array>
#include <filesystem>

#include "Common.hpp"


using namespace std;


constexpr std::string_view moduleName = "pwd";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) PrintWorkingDirectory* PrintWorkingDirectoryConstructor() 
{
    return new PrintWorkingDirectory();
}

#else

__attribute__((visibility("default"))) PrintWorkingDirectory* PrintWorkingDirectoryConstructor() 
{
    return new PrintWorkingDirectory();
}

#endif


PrintWorkingDirectory::PrintWorkingDirectory()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
}

PrintWorkingDirectory::~PrintWorkingDirectory()
{
}

std::string PrintWorkingDirectory::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "PrintWorkingDirectory Module:\n";
	info += "Print the current working directory on the victim machine.\n";
	info += "\nExample:\n";
	info += "- pwd\n";
#endif
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

	c2RetMessage.set_instruction(c2RetMessage.instruction());
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