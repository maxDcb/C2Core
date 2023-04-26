#pragma once

#include "ModuleCmd.hpp"


class ChangeDirectory : public ModuleCmd
{

public:
	ChangeDirectory();
	~ChangeDirectory();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:
	std::string changeDirectory(const std::string& path);

};


#ifdef _WIN32

extern "C" __declspec(dllexport) ChangeDirectory * ChangeDirectoryConstructor();

#endif
