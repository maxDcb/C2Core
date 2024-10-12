#pragma once

#include "ModuleCmd.hpp"


class Rev2self : public ModuleCmd
{

public:
	Rev2self();
	~Rev2self();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:
	std::string rev2self();
};


#ifdef _WIN32

extern "C" __declspec(dllexport) Rev2self * Rev2selfConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Rev2self * Rev2selfConstructor();

#endif