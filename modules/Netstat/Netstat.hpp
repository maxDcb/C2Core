#pragma once

#include "ModuleCmd.hpp"

#ifndef _WIN32
#include <unordered_map>
namespace netstat_detail
{
using SocketOwners = std::unordered_map<std::string, std::string>;
std::string formatProcSocketLine(const std::string& line, const char* protocol, bool ipv6,
    const SocketOwners& owners = {});
}
#endif

class Netstat : public ModuleCmd
{
public:
    Netstat();
    ~Netstat();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int osCompatibility()
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
    std::string runNetstat();
};

#ifdef _WIN32
extern "C" __declspec(dllexport) Netstat* NetstatConstructor();
#else
extern "C" __attribute__((visibility("default"))) Netstat* NetstatConstructor();
#endif
