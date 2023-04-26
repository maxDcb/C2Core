#pragma once

#include "ModuleCmd.hpp"


class ListProcesses : public ModuleCmd
{

public:
	ListProcesses();
	~ListProcesses();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:
	std::string listProcesses();

};


#ifdef _WIN32

extern "C" __declspec(dllexport) ListProcesses * ListProcessesConstructor();

#endif