#pragma once

#include "ModuleCmd.hpp"


class CoffLoader : public ModuleCmd
{

public:
	CoffLoader();
	~CoffLoader();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);
	int osCompatibility() 
	{
        return OS_WINDOWS;
    }

private:
	std::string coffLoader(std::string& payload, std::string& functionName, std::string& argsCompressed);

};


#ifdef _WIN32

extern "C" __declspec(dllexport) CoffLoader * A_CoffLoaderConstructor();

#else

extern "C"  __attribute__((visibility("default"))) CoffLoader * CoffConstructor();

#endif
