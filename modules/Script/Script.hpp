#pragma once

#include "ModuleCmd.hpp"


class Script : public ModuleCmd
{

public:
	Script();
	~Script();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:

};


#ifdef _WIN32

extern "C" __declspec(dllexport) Script * ScriptConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Script * ScriptConstructor();

#endif