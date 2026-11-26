#include "MessageTestHelpers.hpp"

#include <iostream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace
{
struct ModuleCase
{
    const char* name;
    const char* library;
    const char* constructor;
};

#ifdef _WIN32
const ModuleCase cases[] = {
#ifdef ASSEMBLYEXEC_MODULE_PATH
    {"assemblyExec", ASSEMBLYEXEC_MODULE_PATH, "A_AssemblyExecConstructor"},
#endif
#ifdef CHISEL_MODULE_PATH
    {"chisel", CHISEL_MODULE_PATH, "A_ChiselConstructor"},
#endif
#ifdef COFFLOADER_MODULE_PATH
    {"coffLoader", COFFLOADER_MODULE_PATH, "A_CoffLoaderConstructor"},
#endif
#ifdef DOTNETEXEC_MODULE_PATH
    {"dotnetExec", DOTNETEXEC_MODULE_PATH, "DotnetExecConstructor"},
#endif
#ifdef EVASION_MODULE_PATH
    {"evasion", EVASION_MODULE_PATH, "A_EvasionConstructor"},
#endif
#ifdef INJECT_MODULE_PATH
    {"inject", INJECT_MODULE_PATH, "A_InjectConstructor"},
#endif
#ifdef KERBEROSUSETICKET_MODULE_PATH
    {"kerberosUseTicket", KERBEROSUSETICKET_MODULE_PATH, "KerberosUseTicketConstructor"},
#endif
#ifdef KEYLOGGER_MODULE_PATH
    {"keyLogger", KEYLOGGER_MODULE_PATH, "KeyLoggerConstructor"},
#endif
#ifdef MINIDUMP_MODULE_PATH
    {"miniDump", MINIDUMP_MODULE_PATH, "MiniDumpConstructor"},
#endif
#ifdef POWERSHELL_MODULE_PATH
    {"powershell", POWERSHELL_MODULE_PATH, "PowershellConstructor"},
#endif
#ifdef PWSH_MODULE_PATH
    {"pwSh", PWSH_MODULE_PATH, "PwShConstructor"},
#endif
};
#else
const ModuleCase cases[] = {
#ifdef ASSEMBLYEXEC_MODULE_PATH
    {"assemblyExec", ASSEMBLYEXEC_MODULE_PATH, "AssemblyExecConstructor"},
#endif
#ifdef CHISEL_MODULE_PATH
    {"chisel", CHISEL_MODULE_PATH, "ChiselConstructor"},
#endif
#ifdef COFFLOADER_MODULE_PATH
    {"coffLoader", COFFLOADER_MODULE_PATH, "CoffConstructor"},
#endif
#ifdef DOTNETEXEC_MODULE_PATH
    {"dotnetExec", DOTNETEXEC_MODULE_PATH, "DotnetExecConstructor"},
#endif
#ifdef EVASION_MODULE_PATH
    {"evasion", EVASION_MODULE_PATH, "EvasionConstructor"},
#endif
#ifdef INJECT_MODULE_PATH
    {"inject", INJECT_MODULE_PATH, "InjectConstructor"},
#endif
#ifdef KERBEROSUSETICKET_MODULE_PATH
    {"kerberosUseTicket", KERBEROSUSETICKET_MODULE_PATH, "KerberosUseTicketConstructor"},
#endif
#ifdef KEYLOGGER_MODULE_PATH
    {"keyLogger", KEYLOGGER_MODULE_PATH, "KeyLoggerConstructor"},
#endif
#ifdef MINIDUMP_MODULE_PATH
    {"miniDump", MINIDUMP_MODULE_PATH, "MiniDumpConstructor"},
#endif
#ifdef POWERSHELL_MODULE_PATH
    {"powershell", POWERSHELL_MODULE_PATH, "PowershellConstructor"},
#endif
#ifdef PWSH_MODULE_PATH
    {"pwSh", PWSH_MODULE_PATH, "PwShConstructor"},
#endif
};
#endif

bool check(const ModuleCase& test)
{
#ifdef _WIN32
    HMODULE library = LoadLibraryA(test.library);
    if (!library)
    {
        std::cerr << test.name << ": could not load module\n";
        return false;
    }
    auto constructor = reinterpret_cast<ModuleCmd* (*)()>(GetProcAddress(library, test.constructor));
#else
    void* library = dlopen(test.library, RTLD_NOW | RTLD_LOCAL);
    if (!library)
    {
        std::cerr << test.name << ": " << dlerror() << '\n';
        return false;
    }
    auto constructor = reinterpret_cast<ModuleCmd* (*)()>(dlsym(library, test.constructor));
#endif
    if (!constructor)
    {
        std::cerr << test.name << ": constructor is not exported\n";
        return false;
    }

    ModuleCmd* executor = constructor();
    ModuleCmd* receiver = constructor();
    bool ok = executor != nullptr && receiver != nullptr;
    if (ok)
    {
        ok = executor->osCompatibility() == OS_WINDOWS;
        C2Message codeOnly;
        codeOnly.set_errorCode(C2CORE_ERROR_UNSUPPORTED_PLATFORM);
        std::string error;
        receiver->errorCodeToMsg(test_helpers::roundTripMessage(codeOnly), error);
        ok &= error == "Module requires Windows.";
        C2Message prepared;
        prepared.set_instruction(test.name);
        C2Message request = test_helpers::roundTripMessage(prepared);
        C2Message rawResponse;
        executor->process(request, rawResponse);
        const C2Message response = test_helpers::roundTripMessage(rawResponse);
        ok &= response.instruction() == request.instruction()
#ifdef _WIN32
            && response.errorCode() == C2CORE_ERROR_INVALID_REQUEST
#else
            && response.errorCode() == C2CORE_ERROR_UNSUPPORTED_PLATFORM
#endif
            && response.returnvalue().empty();
#ifdef _WIN32
        C2Message invalidCodeOnly;
        invalidCodeOnly.set_errorCode(C2CORE_ERROR_INVALID_REQUEST);
        receiver->errorCodeToMsg(test_helpers::roundTripMessage(invalidCodeOnly), error);
        ok &= error == "Invalid module request.";
        if (!ok)
            std::cerr << test.name << ": compatibility=" << executor->osCompatibility()
                << ", response code=" << response.errorCode()
                << ", instruction=" << response.instruction()
                << ", return size=" << response.returnvalue().size()
                << ", error=" << error << '\n';
#endif
    }
    if (!ok)
        std::cerr << test.name << ": platform response contract failed\n";

    // ModuleCmd has no virtual destructor; objects live until this short test exits.
    return ok;
}
}

int main()
{
    bool ok = true;
    for (const auto& test : cases)
        ok &= check(test);
    return ok ? 0 : 1;
}
