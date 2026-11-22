#include "../../ReversePortForward/ReversePortForward.hpp"
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
    HMODULE library = LoadLibraryA(REVERSEPORTFORWARD_MODULE_PATH);
    if (!library)
        return false;
    const bool found = GetProcAddress(library, "ReversePortForwardConstructor") != nullptr;
    FreeLibrary(library);
#else
    void* library = dlopen(REVERSEPORTFORWARD_MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
    if (!library)
        return false;
    const bool found = dlsym(library, "ReversePortForwardConstructor") != nullptr;
    dlclose(library);
#endif
    return found;
}
}

int main()
{
    using test_helpers::expect;
    using test_helpers::roundTripMessage;
    bool ok = expect(hasConstructor(), "the shared library exports its original constructor");
    ReversePortForward preparer;
    ReversePortForward executor;
    ReversePortForward receiver;
    ok &= expect(preparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "reverse forwarding declares both platforms");
    C2Message invalid;
    std::vector<std::string> incomplete = {"reversePortForward", "8080"};
    ok &= expect(preparer.init(incomplete, invalid) == -1,
        "init rejects missing destination parameters");

    C2Message badRequest;
    badRequest.set_instruction("reversePortForward");
    badRequest.set_cmd("start");
    badRequest.set_args("0 127.0.0.1 80");
    C2Message transported = roundTripMessage(badRequest);
    C2Message badRaw;
    executor.process(transported, badRaw);
    const C2Message badResponse = roundTripMessage(badRaw);
    ok &= expect(badResponse.errorCode() == 3 && badResponse.returnvalue().empty(),
        "an invalid transported port returns a code-only failure");
    for (int code = 1; code <= 5; ++code)
    {
        C2Message codeOnly;
        codeOnly.set_errorCode(code);
        std::string message;
        receiver.errorCodeToMsg(roundTripMessage(codeOnly), message);
        ok &= expect(!message.empty(), "a received forward error code has a stable message");
    }
    C2Message noError;
    noError.set_errorCode(0);
    std::string stale = "earlier error";
    receiver.errorCodeToMsg(roundTripMessage(noError), stale);
    ok &= expect(stale.empty(), "a successful response clears an earlier error");

    C2Message failedEvent;
    failedEvent.set_errorCode(4);
    failedEvent.set_cmd("send");
    failedEvent.set_args("data:1");
    failedEvent.set_inputfile("127.0.0.1");
    failedEvent.set_outputfile("9");
    failedEvent.set_data("must-not-forward");
    ok &= expect(receiver.followUp(roundTripMessage(failedEvent)) == 0,
        "followUp ignores a failed received event");
    C2Message noRecurring;
    ok &= expect(executor.recurringExec(noRecurring) == 0,
        "recurringExec stays idle before a forward starts");
    return ok ? 0 : 1;
}
