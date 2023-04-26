#pragma once

#include "ModuleCmd.hpp"


class MakeToken : public ModuleCmd
{

public:
	MakeToken();
	~MakeToken();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:
	std::string makeToken(const std::string& username, const std::string& domain, const std::string& password);
};


#ifdef _WIN32

extern "C" __declspec(dllexport) MakeToken * MakeTokenConstructor();

#endif
