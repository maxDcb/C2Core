#include "ModuleCmd.hpp"


#ifdef __linux__ 

#elif _WIN32

#endif


using namespace std;


ModuleCmd::ModuleCmd(const std::string& name)
{
	m_name=name;
}

ModuleCmd::~ModuleCmd()
{
}

