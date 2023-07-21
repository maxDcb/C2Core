#pragma once

#include "ModuleCmd.hpp"


class WmiExec : public ModuleCmd
{

public:
	WmiExec();
	~WmiExec();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:

};


#ifdef _WIN32

extern "C" __declspec(dllexport) WmiExec * WmiExecConstructor();

#endif
