#include "Netstat.hpp"
#include "Common.hpp"

#include <cstring>
#include <array>
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
#include <filesystem>
#include <algorithm>
#endif

using namespace std;

constexpr std::string_view moduleName = "netstat";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifndef _WIN32
namespace netstat_detail
{
namespace
{
int hexDigit(char digit)
{
    if (digit >= '0' && digit <= '9') return digit - '0';
    if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
    if (digit >= 'A' && digit <= 'F') return digit - 'A' + 10;
    return -1;
}

bool hexByte(const std::string& text, size_t offset, unsigned char& byte)
{
    if (offset + 1 >= text.size()) return false;
    const int high = hexDigit(text[offset]);
    const int low = hexDigit(text[offset + 1]);
    if (high < 0 || low < 0) return false;
    byte = static_cast<unsigned char>((high << 4) | low);
    return true;
}

bool decodeAddress(const std::string& field, bool ipv6, std::string& address)
{
    const size_t separator = field.find(':');
    if (separator == std::string::npos || field.find(':', separator + 1) != std::string::npos)
        return false;
    const std::string ipHex = field.substr(0, separator);
    const std::string portHex = field.substr(separator + 1);
    if (ipHex.size() != (ipv6 ? 32u : 8u) || portHex.empty() || portHex.size() > 4)
        return false;
    unsigned port = 0;
    for (char digit : portHex)
    {
        const int value = hexDigit(digit);
        if (value < 0) return false;
        port = (port << 4) | static_cast<unsigned>(value);
    }

    std::array<unsigned char, 16> bytes{};
    const size_t count = ipv6 ? 16 : 4;
    for (size_t i = 0; i < count; ++i)
    {
        unsigned char byte = 0;
        if (!hexByte(ipHex, i * 2, byte)) return false;
        // /proc/net stores each 32-bit address word in host byte order.
        bytes[(i / 4) * 4 + (3 - i % 4)] = byte;
    }
    char rendered[INET6_ADDRSTRLEN]{};
    if (inet_ntop(ipv6 ? AF_INET6 : AF_INET, bytes.data(), rendered, sizeof(rendered)) == nullptr)
        return false;
    address = ipv6 ? '[' + std::string(rendered) + "]:" + std::to_string(port)
                   : std::string(rendered) + ':' + std::to_string(port);
    return true;
}

std::string stateName(const std::string& state, const char* protocol)
{
    if (state == "01") return "ESTABLISHED";
    if (state == "02") return "SYN_SENT";
    if (state == "03") return "SYN_RECV";
    if (state == "04") return "FIN_WAIT1";
    if (state == "05") return "FIN_WAIT2";
    if (state == "06") return "TIME_WAIT";
    if (state == "07") return std::strncmp(protocol, "UDP", 3) == 0 ? "UNCONN" : "CLOSE";
    if (state == "08") return "CLOSE_WAIT";
    if (state == "09") return "LAST_ACK";
    if (state == "0A") return "LISTEN";
    if (state == "0B") return "CLOSING";
    if (state == "0C") return "NEW_SYN_RECV";
    return "UNKNOWN";
}

SocketOwners socketOwners()
{
    namespace fs = std::filesystem;
    SocketOwners owners;
    std::error_code error;
    fs::directory_iterator processes("/proc", fs::directory_options::skip_permission_denied, error);
    size_t visitedDescriptors = 0;
    const fs::directory_iterator end;
    for (; !error && processes != end; processes.increment(error))
    {
        const auto& process = *processes;
        const std::string pid = process.path().filename().string();
        if (pid.empty() || !std::all_of(pid.begin(), pid.end(), [](unsigned char ch) { return ch >= '0' && ch <= '9'; }))
            continue;
        const fs::path descriptors = process.path() / "fd";
        fs::directory_iterator files(descriptors, fs::directory_options::skip_permission_denied, error);
        if (error) { error.clear(); continue; }
        std::string processName;
        std::ifstream nameFile(process.path() / "comm");
        std::getline(nameFile, processName);
        processName = processName.substr(0, 64);
        for (; !error && files != end; files.increment(error))
        {
            if (++visitedDescriptors > 50000) return owners;
            const fs::path target = fs::read_symlink(files->path(), error);
            if (error) { error.clear(); continue; }
            const std::string link = target.string();
            if (link.rfind("socket:[", 0) != 0 || link.back() != ']') continue;
            const std::string inode = link.substr(8, link.size() - 9);
            owners.emplace(inode, pid + '/' + processName);
        }
        error.clear(); // a process may exit while its fd directory is being read
    }
    return owners;
}
} // namespace

std::string formatProcSocketLine(const std::string& line, const char* protocol, bool ipv6,
    const SocketOwners& owners)
{
    std::istringstream fields(line);
    std::string slot, local, remote, state;
    if (!(fields >> slot >> local >> remote >> state)) return {};
    std::string localAddress, remoteAddress;
    if (!decodeAddress(local, ipv6, localAddress) || !decodeAddress(remote, ipv6, remoteAddress))
        return {};
    std::string formatted = std::string(protocol) + ' ' + localAddress + " -> " + remoteAddress
        + " State:" + stateName(state, protocol) + '(' + state + ')';
    std::string queue, timer, retransmits, uid, timeout, inode;
    if (fields >> queue >> timer >> retransmits >> uid >> timeout >> inode)
    {
        const auto owner = owners.find(inode);
        formatted += " Owner:" + (owner == owners.end() ? std::string("unknown") : owner->second);
    }
    return formatted + '\n';
}
} // namespace netstat_detail
#endif

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
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    c2Message.set_instruction(splitedCmd[0]);
#endif

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
    const netstat_detail::SocketOwners owners = netstat_detail::socketOwners();
    auto parse = [&](const std::string& path, const char* proto, bool ipv6)
    {
        std::ifstream f(path);
        if(!f) return;
        std::string line;
        std::getline(f, line); // skip header
        while(std::getline(f, line))
        {
            result += netstat_detail::formatProcSocketLine(line, proto, ipv6, owners);
        }
    };
    parse("/proc/net/tcp", "TCP", false);
    parse("/proc/net/udp", "UDP", false);
    parse("/proc/net/tcp6", "TCP6", true);
    parse("/proc/net/udp6", "UDP6", true);
    return result;
#endif
}

