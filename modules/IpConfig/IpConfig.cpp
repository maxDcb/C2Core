#include "IpConfig.hpp"
#include "Common.hpp"

#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sstream>
#endif

using namespace std;

constexpr std::string_view moduleName = "ipConfig";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32
__declspec(dllexport) IpConfig* IpConfigConstructor()
{
    return new IpConfig();
}
#else
__attribute__((visibility("default"))) IpConfig* IpConfigConstructor()
{
    return new IpConfig();
}
#endif

IpConfig::IpConfig()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

IpConfig::~IpConfig()
{
}

std::string IpConfig::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "ipConfig:\n";
    info += "Show local IP configuration.\n";
#endif
    return info;
}

int IpConfig::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (splitedCmd.size() != 1 || splitedCmd[0] != std::string(moduleName))
    {
        c2Message.set_returnvalue("Usage: ipConfig");
        return -1;
    }
    c2Message.set_instruction(splitedCmd[0]);
#endif

    return 0;
}

int IpConfig::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    int errorCode = 0;
    std::string out = runIpconfig(errorCode);
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_returnvalue(out);
    c2RetMessage.set_errorCode(errorCode);
    return 0;
}

int IpConfig::errorCodeToMsg(const C2Message& response, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (response.errorCode() == 1)
        errorMsg = "Failed to enumerate network interfaces.";
#else
    (void)response;
    (void)errorMsg;
#endif
    return 0;
}


#ifdef _WIN32
std::string WideToUTF8(const PWCHAR wideStr) {
    if (!wideStr) return "";

    int len = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    if (len == 0) return "";

    std::string result(len, 0);
    if (WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, &result[0], len, nullptr, nullptr) == 0)
        return "";
    result.resize(len - 1); // exclude null terminator

    return result;
}
#endif


std::string IpConfig::runIpconfig(int& errorCode)
{
#ifdef _WIN32
    std::string result;
    ULONG size = 0;
    const ULONG probe = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size);
    if (probe != ERROR_BUFFER_OVERFLOW || size == 0)
    {
        errorCode = 1;
        return result;
    }
    std::vector<IP_ADAPTER_ADDRESSES> buf(size / sizeof(IP_ADAPTER_ADDRESSES) + 1);
    PIP_ADAPTER_ADDRESSES addr = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    if(GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, addr, &size) == NO_ERROR)
    {
        for(auto p = addr; p; p = p->Next)
        {
            result += WideToUTF8(p->FriendlyName) + "\n";
            for(PIP_ADAPTER_UNICAST_ADDRESS unicast = p->FirstUnicastAddress; unicast; unicast = unicast->Next)
            {
                char ip[INET6_ADDRSTRLEN];
                void* sa = &((struct sockaddr_in*)unicast->Address.lpSockaddr)->sin_addr;
                int family = unicast->Address.lpSockaddr->sa_family;
                if(family == AF_INET)
                {
                    inet_ntop(AF_INET, sa, ip, sizeof(ip));
                }
                else if(family == AF_INET6)
                {
                    sa = &((struct sockaddr_in6*)unicast->Address.lpSockaddr)->sin6_addr;
                    inet_ntop(AF_INET6, sa, ip, sizeof(ip));
                }
                else
                    continue;
                result += "  " ;
                result += ip;
                result += "\n";
            }
        }
    }
    else
        errorCode = 1;
    return result;
#else
    std::string result;
    struct ifaddrs* ifa = nullptr;
    if(getifaddrs(&ifa) == 0)
    {
        for(auto p = ifa; p; p = p->ifa_next)
        {
            if(!p->ifa_addr) continue;
            int family = p->ifa_addr->sa_family;
            char host[INET6_ADDRSTRLEN];
            if(family == AF_INET)
            {
                inet_ntop(AF_INET, &((struct sockaddr_in*)p->ifa_addr)->sin_addr, host, sizeof(host));
            }
            else if(family == AF_INET6)
            {
                inet_ntop(AF_INET6, &((struct sockaddr_in6*)p->ifa_addr)->sin6_addr, host, sizeof(host));
            }
            else
                continue;
            result += p->ifa_name; result += " "; result += host; result += "\n";
        }
        freeifaddrs(ifa);
    }
    else
        errorCode = 1;
    return result;
#endif
}

