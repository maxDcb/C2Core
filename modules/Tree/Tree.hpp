#pragma once

#include "ModuleCmd.hpp"


class Tree : public ModuleCmd
{

public:
	Tree();
	~Tree();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:
	std::string iterProcess(const std::string& path, int depth);

};


#ifdef _WIN32

extern "C" __declspec(dllexport) Tree * TreeConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Tree * TreeConstructor();

#endif
