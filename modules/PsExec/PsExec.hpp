#pragma once

#include "ModuleCmd.hpp"


class PsExec : public ModuleCmd
{

public:
	PsExec();
	~PsExec();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:

};


#ifdef _WIN32

extern "C" __declspec(dllexport) PsExec * PsExecConstructor();

#endif
