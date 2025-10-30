#include "EnumerateRdpSessions.hpp"

#include "Common.hpp"

#include <iomanip>
#include <sstream>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")
#endif

using namespace std;

constexpr std::string_view moduleNameEnumerateRdpSessions = "enumerateRdpSessions";
constexpr unsigned long long moduleHashEnumerateRdpSessions = djb2(moduleNameEnumerateRdpSessions);

#ifdef _WIN32
extern "C" __declspec(dllexport) EnumerateRdpSessions* EnumerateRdpSessionsConstructor()
{
    return new EnumerateRdpSessions();
}
#else
extern "C" __attribute__((visibility("default"))) EnumerateRdpSessions* EnumerateRdpSessionsConstructor()
{
    return new EnumerateRdpSessions();
}
#endif

EnumerateRdpSessions::EnumerateRdpSessions()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleNameEnumerateRdpSessions), moduleHashEnumerateRdpSessions)
#else
    : ModuleCmd("", moduleHashEnumerateRdpSessions)
#endif
{
}

EnumerateRdpSessions::~EnumerateRdpSessions() = default;

std::string EnumerateRdpSessions::getInfo()
{
    std::ostringstream info;
#ifdef BUILD_TEAMSERVER
    info << "enumerateRdpSessions:\n";
    info << "Enumerate local or remote RDP sessions using the WTS APIs." << '\n';
    info << "Usage:" << '\n';
    info << "  enumerateRdpSessions [options]" << '\n';
    info << "Options:" << '\n';
    info << "  -s <server>    Target host name or IP. Defaults to the local system." << '\n';
    info << "Examples:" << '\n';
    info << "  enumerateRdpSessions" << '\n';
    info << "  enumerateRdpSessions -s fileserver" << '\n';
#endif
    return info.str();
}

std::string EnumerateRdpSessions::packParameters(const Parameters& params) const
{
    std::string packed;
    packed.append(params.server);
    packed.push_back('\0');
    return packed;
}

EnumerateRdpSessions::Parameters EnumerateRdpSessions::unpackParameters(const std::string& data) const
{
    Parameters params;
    auto end = data.find('\0');
    if (end == std::string::npos)
    {
        params.server = data;
    }
    else
    {
        params.server = data.substr(0, end);
    }
    return params;
}


int EnumerateRdpSessions::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    std::vector<std::string> args = regroupStrings(splitedCmd);
    if (args.empty())
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    if (args.size() > 1 && (args[1] == "help" || args[1] == "--help"))
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    Parameters params;
    for (size_t i = 1; i < args.size(); ++i)
    {
        const std::string& current = args[i];
        if (current == "-s" && i + 1 < args.size())
        {
            params.server = args[++i];
        }
        else if (!current.empty() && current[0] != '-')
        {
            params.server = current;
        }
        else
        {
            c2Message.set_returnvalue(getInfo());
            return -1;
        }
    }

    c2Message.set_instruction(args[0]);
    c2Message.set_cmd(packParameters(params));
#endif
    return 0;
}

int EnumerateRdpSessions::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.cmd());

#ifdef _WIN32
    Parameters params = unpackParameters(c2Message.cmd());

    HANDLE serverHandle = WTS_CURRENT_SERVER_HANDLE;
    bool shouldClose = false;
    if (!params.server.empty())
    {
        serverHandle = WTSOpenServerA(const_cast<LPSTR>(params.server.c_str()));
        if (serverHandle == nullptr)
        {
            DWORD lastError = GetLastError();
            std::ostringstream err;
            err << "Failed to open server '" << params.server << "' (error " << lastError << ").";
            c2RetMessage.set_errorCode(ERROR_OPEN_SERVER);
            c2RetMessage.set_returnvalue(err.str());
            return 0;
        }
        shouldClose = true;
    }

    PWTS_SESSION_INFOA sessionInfo = nullptr;
    DWORD sessionCount = 0;
    if (!WTSEnumerateSessionsA(serverHandle, 0, 1, &sessionInfo, &sessionCount))
    {
        DWORD lastError = GetLastError();
        if (shouldClose)
        {
            WTSCloseServer(serverHandle);
        }
        std::ostringstream err;
        err << "Failed to enumerate sessions (error " << lastError << ").";
        c2RetMessage.set_errorCode(ERROR_ENUMERATE_SESSIONS);
        c2RetMessage.set_returnvalue(err.str());
        return 0;
    }

    auto cleanup = [&]()
    {
        if (sessionInfo)
        {
            WTSFreeMemory(sessionInfo);
            sessionInfo = nullptr;
        }
        if (shouldClose && serverHandle)
        {
            WTSCloseServer(serverHandle);
            shouldClose = false;
        }
    };

    auto queryString = [&](DWORD sessionId, WTS_INFO_CLASS infoClass) -> std::string
    {
        LPSTR buffer = nullptr;
        DWORD bytes = 0;
        std::string value;
        if (WTSQuerySessionInformationA(serverHandle, sessionId, infoClass, &buffer, &bytes) && buffer)
        {
            value.assign(buffer);
        }
        if (buffer)
        {
            WTSFreeMemory(buffer);
        }
        return value;
    };

    auto queryClientAddress = [&](DWORD sessionId) -> std::string
    {
        PWTS_CLIENT_ADDRESS address = nullptr;
        DWORD bytes = 0;
        std::string result = "-";
        if (WTSQuerySessionInformationA(serverHandle, sessionId, WTSClientAddress, reinterpret_cast<LPSTR*>(&address), &bytes) && address)
        {
            switch (address->AddressFamily)
            {
            case 0:
                result = "-";
                break;
            case 2:
            {
                std::ostringstream oss;
                oss << static_cast<int>(address->Address[2]) << '.'
                    << static_cast<int>(address->Address[3]) << '.'
                    << static_cast<int>(address->Address[4]) << '.'
                    << static_cast<int>(address->Address[5]);
                result = oss.str();
                break;
            }
            case 17:
                result = "NetBIOS";
                break;
            default:
                result = "Unknown";
                break;
            }
        }
        if (address)
        {
            WTSFreeMemory(address);
        }
        return result;
    };

    auto stateToString = [](WTS_CONNECTSTATE_CLASS state) -> std::string
    {
        switch (state)
        {
        case WTSActive:
            return "Active";
        case WTSConnected:
            return "Connected";
        case WTSConnectQuery:
            return "ConnectQuery";
        case WTSShadow:
            return "Shadow";
        case WTSDisconnected:
            return "Disconnected";
        case WTSIdle:
            return "Idle";
        case WTSListen:
            return "Listen";
        case WTSReset:
            return "Reset";
        case WTSDown:
            return "Down";
        default:
            return "Unknown";
        }
    };

    std::ostringstream output;
    output << std::left
           << std::setw(20) << "UserDomain"
           << std::setw(25) << "UserName"
           << std::setw(18) << "SessionName"
           << std::setw(12) << "SessionID"
           << std::setw(16) << "State"
           << std::setw(20) << "SourceAddress"
           << "SourceClientName" << '\n';

    bool anySession = false;
    for (DWORD i = 0; i < sessionCount; ++i)
    {
        const WTS_SESSION_INFOA& si = sessionInfo[i];
        if (si.SessionId > 2048)
        {
            continue;
        }

        std::string userName = queryString(si.SessionId, WTSUserName);
        if (userName.empty())
        {
            continue;
        }
        std::string userDomain = queryString(si.SessionId, WTSDomainName);
        std::string clientName = queryString(si.SessionId, WTSClientName);
        std::string clientAddress = queryClientAddress(si.SessionId);

        output << std::left
               << std::setw(20) << (userDomain.empty() ? "-" : userDomain)
               << std::setw(25) << userName
               << std::setw(18) << (si.pWinStationName ? si.pWinStationName : "")
               << std::setw(12) << si.SessionId
               << std::setw(16) << stateToString(si.State)
               << std::setw(20) << clientAddress
               << (clientName.empty() ? "-" : clientName)
               << '\n';
        anySession = true;
    }

    if (!anySession)
    {
        output << "No sessions found." << '\n';
    }

    c2RetMessage.set_returnvalue(output.str());

    cleanup();
#else
    (void)c2Message;
    c2RetMessage.set_errorCode(ERROR_WINDOWS_ONLY);
    c2RetMessage.set_returnvalue("Only available on Windows.");
#endif
    return 0;
}

int EnumerateRdpSessions::followUp(const C2Message& /*c2RetMessage*/)
{
    return 0;
}

int EnumerateRdpSessions::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    if (c2RetMessage.errorCode() > 0)
    {
        errorMsg = c2RetMessage.returnvalue();
    }
#endif
    return 0;
}
