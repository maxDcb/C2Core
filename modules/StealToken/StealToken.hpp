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
	int osCompatibility() 
	{
        return OS_WINDOWS;
    }

private:
	std::string stealToken(int pid);
};


#ifdef _WIN32

extern "C" __declspec(dllexport) StealToken * StealTokenConstructor();

#else

extern "C"  __attribute__((visibility("default"))) StealToken * StealTokenConstructor();

#endif