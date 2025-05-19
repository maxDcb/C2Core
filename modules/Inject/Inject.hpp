#pragma once

#include "ModuleCmd.hpp"

#ifdef _WIN32
	#include <Windows.h>
#endif

class Inject : public ModuleCmd
{

public:
	Inject();
	~Inject();

	std::string getInfo();

	int initConfig(const nlohmann::json &config);
	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);
	int osCompatibility() 
	{
        return OS_WINDOWS;
    }

private:
	std::string m_processToSpawn;
	bool m_useSyscall;

};


#ifdef _WIN32

extern "C" __declspec(dllexport) Inject * A_InjectConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Inject * InjectConstructor();

#endif
