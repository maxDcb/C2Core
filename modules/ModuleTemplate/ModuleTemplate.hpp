#pragma once

#include "ModuleCmd.hpp"


class ModuleTemplate : public ModuleCmd
{

public:
	ModuleTemplate();
	~ModuleTemplate();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);
	int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg);
	int followUp(const C2Message &c2RetMessage);

private:

};


#ifdef _WIN32

extern "C" __declspec(dllexport) ModuleTemplate * ModuleTemplateConstructor();

#else

extern "C"  __attribute__((visibility("default"))) ModuleTemplate * ModuleTemplateConstructor();

#endif
