#pragma once

#include "ModuleCmd.hpp"
#include "Common.hpp"


class MiniDump : public ModuleCmd
{
public:
	MiniDump();
	~MiniDump();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);
	int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg);
	int osCompatibility() 
	{
        return OS_WINDOWS;
    }

private:
	
};


#ifdef _WIN32

extern "C" __declspec(dllexport) MiniDump * MiniDumpConstructor();

#else

extern "C"  __attribute__((visibility("default"))) MiniDump * MiniDumpConstructor();

#endif
