#pragma once

#include "ModuleCmd.hpp"


class KerberosUseTicket : public ModuleCmd
{

public:
	KerberosUseTicket();
	~KerberosUseTicket();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

private:
	std::string importTicket(const std::string& ticket);
};


#ifdef _WIN32

extern "C" __declspec(dllexport) KerberosUseTicket * KerberosUseTicketConstructor();

#endif
