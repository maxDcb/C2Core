#include "../../EnumerateRdpSessions/EnumerateRdpSessions.hpp"
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
    HMODULE library = LoadLibraryA(ENUMERATERDPSESSIONS_MODULE_PATH);
    if (!library)
        return false;
    const bool found = GetProcAddress(library, "EnumerateRdpSessionsConstructor") != nullptr;
    FreeLibrary(library);
#else
    void* library = dlopen(ENUMERATERDPSESSIONS_MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
    if (!library)
        return false;
    const bool found = dlsym(library, "EnumerateRdpSessionsConstructor") != nullptr;
    dlclose(library);
#endif
    return found;
}
}

int main()
{
    using test_helpers::expect;
    using test_helpers::roundTripMessage;
    bool ok = expect(hasConstructor(), "the Windows-only module compiles on both platforms and exports its constructor");
    EnumerateRdpSessions preparer;
    EnumerateRdpSessions executor;
    EnumerateRdpSessions receiver;
    ok &= expect(preparer.osCompatibility() == OS_WINDOWS,
        "RDP enumeration declares Windows-only behavior");
    C2Message invalid;
    std::vector<std::string> missingValue = {"enumerateRdpSessions", "-s"};
    ok &= expect(preparer.init(missingValue, invalid) == -1,
        "init rejects an incomplete server option");

    const auto exchange = test_helpers::exchangeMessages(preparer, executor,
        {"enumerateRdpSessions"});
    ok &= expect(exchange.request.instruction() == "enumerateRdpSessions"
        && exchange.response.instruction() == "enumerateRdpSessions",
        "request and response survive serialization between instances");
#ifdef _WIN32
    ok &= expect((exchange.response.errorCode() == 0 && !exchange.response.returnvalue().empty())
        || (exchange.response.errorCode() == EnumerateRdpSessions::ERROR_ENUMERATE_SESSIONS
            && exchange.response.returnvalue().empty()),
        "Windows local enumeration reports a listing or a code-only OS failure");
#else
    ok &= expect(exchange.response.errorCode() == EnumerateRdpSessions::ERROR_WINDOWS_ONLY
        && exchange.response.returnvalue().empty(),
        "Linux reports unsupported behavior with a code-only response");
#endif
    for (int code = 1; code <= 3; ++code)
    {
        C2Message codeOnly;
        codeOnly.set_errorCode(code);
        std::string message;
        receiver.errorCodeToMsg(roundTripMessage(codeOnly), message);
        ok &= expect(!message.empty(), "the received RDP error code has a stable message");
    }
    C2Message success;
    success.set_errorCode(0);
    std::string stale = "earlier error";
    receiver.errorCodeToMsg(roundTripMessage(success), stale);
    ok &= expect(stale.empty(), "success clears an earlier error message");
    C2Message noRecurring;
    ok &= expect(receiver.followUp(exchange.response) == 0
        && executor.recurringExec(noRecurring) == 0,
        "RDP enumeration has no follow-up or recurring work");
    return ok ? 0 : 1;
}
