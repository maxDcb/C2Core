#pragma once

#include "ModuleCmd.hpp"


class Cat : public ModuleCmd
{

public:
	Cat();
	~Cat();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:

};


#ifdef _WIN32

extern "C" __declspec(dllexport) Cat * CatConstructor();

#endif

