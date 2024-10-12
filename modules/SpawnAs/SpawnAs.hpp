#pragma once

#include "ModuleCmd.hpp"


class SpawnAs : public ModuleCmd
{

public:
	SpawnAs();
	~SpawnAs();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:

};


#ifdef _WIN32

extern "C" __declspec(dllexport) SpawnAs * A_SpawnAsConstructor();

#else

extern "C"  __attribute__((visibility("default"))) SpawnAs * SpawnAsConstructor();

#endif
