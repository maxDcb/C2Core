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
    int osCompatibility() 
    {
        return OS_WINDOWS;
    }

private:
    std::string importTicket(const std::string& ticket);
};


#ifdef _WIN32

extern "C" __declspec(dllexport) KerberosUseTicket * KerberosUseTicketConstructor();

#else

extern "C"  __attribute__((visibility("default"))) KerberosUseTicket * KerberosUseTicketConstructor();

#endif
