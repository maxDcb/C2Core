#include "Rev2self.hpp"

#include <cstring>

#ifdef __linux__

#elif _WIN32
#include <windows.h>
#endif

using namespace std;


const std::string moduleName = "rev2self";


#ifdef _WIN32

__declspec(dllexport) Rev2self* Rev2selfConstructor() 
{
    return new Rev2self();
}

#endif

Rev2self::Rev2self()
	: ModuleCmd(moduleName)
{
}

Rev2self::~Rev2self()
{
}

std::string Rev2self::getInfo()
{
	std::string info;
	info += "rev2self:\n";
	info += "Drop the impersonation of a token, created with makeToken\n";
	info += "exemple:\n";
	info += "- rev2self\n";

	return info;
}

int Rev2self::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
    c2Message.set_instruction(m_name);
    c2Message.set_cmd("");

	return 0;
}


int Rev2self::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    std::string out = rev2self();

    c2RetMessage.set_instruction(m_name);
	c2RetMessage.set_cmd("");
	c2RetMessage.set_returnvalue(out);

	return 0;
}


std::string Rev2self::rev2self()
{
	std::string result;

#ifdef __linux__ 

    result += "Rev2self don't work in linux.\n";

#elif _WIN32
    if(RevertToSelf())
        result += "Reverted to self.\n";
    else
        result += "Fail to revert to self.\n";
#endif

	return result;
}