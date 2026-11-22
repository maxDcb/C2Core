#include "../../Registry/Registry.hpp"
#include "../TestHelpers.hpp"
#include "MessageTestHelpers.hpp"

#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace
{
bool hasConstructor()
{
#ifdef _WIN32
    HMODULE library = LoadLibraryA(REGISTRY_MODULE_PATH);
    if (!library)
        return false;
    const bool found = GetProcAddress(library, "RegistryConstructor") != nullptr;
    FreeLibrary(library);
#else
    void* library = dlopen(REGISTRY_MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
    if (!library)
        return false;
    const bool found = dlsym(library, "RegistryConstructor") != nullptr;
    dlclose(library);
#endif
    return found;
}
}

int main()
{
    using test_helpers::expect;
    using test_helpers::roundTripMessage;
    bool ok = expect(hasConstructor(), "the Windows-only registry module exports its constructor on both platforms");
    Registry preparer;
    Registry executor;
    Registry receiver;
    ok &= expect(preparer.osCompatibility() == OS_WINDOWS,
        "registry declares Windows-only behavior");
    C2Message invalid;
    std::vector<std::string> incomplete = {"registry", "query", "-h", "HKLM"};
    ok &= expect(preparer.init(incomplete, invalid) == -1,
        "init rejects missing registry parameters");

    const auto query = test_helpers::exchangeMessages(preparer, executor,
        {"registry", "query", "-h", "HKLM", "-k",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "-n", "ProductName"});
    ok &= expect(query.response.instruction() == "registry"
        && query.response.cmd() == query.request.cmd(),
        "request and response preserve the serialized registry operation");
#ifdef _WIN32
    ok &= expect(query.response.errorCode() == 0
        && query.response.returnvalue().find("Type:") != std::string::npos,
        "Windows executes a read-only registry query successfully");
#else
    ok &= expect(query.response.errorCode() == 9 && query.response.returnvalue().empty(),
        "Linux returns a code-only unsupported response");
#endif
    for (int code = 1; code <= 9; ++code)
    {
        C2Message codeOnly;
        codeOnly.set_errorCode(code);
        std::string message;
        receiver.errorCodeToMsg(roundTripMessage(codeOnly), message);
        ok &= expect(!message.empty(), "the received registry error code has a stable message");
    }
    C2Message success;
    success.set_errorCode(0);
    std::string stale = "earlier error";
    receiver.errorCodeToMsg(roundTripMessage(success), stale);
    ok &= expect(stale.empty(), "success clears an earlier error message");
    C2Message noRecurring;
    ok &= expect(receiver.followUp(query.response) == 0
        && executor.recurringExec(noRecurring) == 0,
        "registry has no follow-up or recurring work");
    return ok ? 0 : 1;
}
