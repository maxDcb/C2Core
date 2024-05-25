#pragma once

#include "ModuleCmd.hpp"

#ifdef _WIN32
	#include <Windows.h>
#endif


class Run : public ModuleCmd
{

public:
	Run();
	~Run();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:
	std::string execBash(const std::string& cmd);

#ifdef _WIN32
	bool m_isProcessRuning;
	HANDLE m_processHandle;
	int killProcess();
#endif
};


#ifdef _WIN32

extern "C" __declspec(dllexport) Run * RunConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Run * RunConstructor();

#endif