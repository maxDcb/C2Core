#pragma once

#include "ModuleCmd.hpp"


class ListDirectory : public ModuleCmd
{

public:
	ListDirectory();
	~ListDirectory();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:
	std::string listDirectory(const std::string& path);

};


#ifdef _WIN32

extern "C" __declspec(dllexport) ListDirectory * ListDirectoryConstructor();

#endif
