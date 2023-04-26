#pragma once

#include "ModuleCmd.hpp"


class PrintWorkingDirectory : public ModuleCmd
{

public:
	PrintWorkingDirectory();
	~PrintWorkingDirectory();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:
	std::string printWorkingDirectory();

};


#ifdef _WIN32

extern "C" __declspec(dllexport) PrintWorkingDirectory * PrintWorkingDirectoryConstructor();

#endif
