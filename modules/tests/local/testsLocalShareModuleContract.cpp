#include "../../EnumerateShares/EnumerateShares.hpp"
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
class ControlledShares : public EnumerateShares
{
protected:
    bool runEnum(const std::string& host, std::string& result) override
    {
        if (host == "unavailable")
            return false;
        if (host == "with-share")
            result = "Public\n";
        return true;
    }
};

bool hasConstructor()
{
#ifdef _WIN32
    HMODULE library = LoadLibraryA(ENUMERATESHARES_MODULE_PATH);
    if (!library)
        return false;
    const bool found = GetProcAddress(library, "EnumerateSharesConstructor") != nullptr;
    FreeLibrary(library);
#else
    void* library = dlopen(ENUMERATESHARES_MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
    if (!library)
        return false;
    const bool found = dlsym(library, "EnumerateSharesConstructor") != nullptr;
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
    EnumerateShares preparer;
    ControlledShares executor;
    EnumerateShares receiver;
    ok &= expect(preparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "share enumeration declares both platforms");
    C2Message invalid;
    std::vector<std::string> noArgs;
    ok &= expect(preparer.init(noArgs, invalid) == -1,
        "init rejects an empty command");

    const auto listing = test_helpers::exchangeMessages(preparer, executor,
        {"enumerateShares", "with-share"});
    ok &= expect(listing.request.cmd() == "with-share"
        && listing.response.instruction() == "enumerateShares"
        && listing.response.errorCode() == 0
        && listing.response.returnvalue() == "Public\n",
        "a serialized request returns the controlled share listing");
    const auto empty = test_helpers::exchangeMessages(preparer, executor,
        {"enumerateShares"});
    ok &= expect(empty.response.errorCode() == 0 && empty.response.returnvalue().empty(),
        "an empty share listing remains a success");
    const auto failure = test_helpers::exchangeMessages(preparer, executor,
        {"enumerateShares", "unavailable"});
    ok &= expect(failure.response.errorCode() == 1
        && failure.response.returnvalue().empty(),
        "an enumeration failure transports a code-only response");
    C2Message codeOnly;
    codeOnly.set_errorCode(1);
    std::string error;
    receiver.errorCodeToMsg(roundTripMessage(codeOnly), error);
    ok &= expect(error == "Failed to enumerate shares.",
        "a separate receiver translates the code without executor state");
    error = "earlier error";
    receiver.errorCodeToMsg(empty.response, error);
    ok &= expect(error.empty(), "success clears an earlier error");
    C2Message noRecurring;
    ok &= expect(receiver.followUp(listing.response) == 0
        && executor.recurringExec(noRecurring) == 0,
        "share enumeration uses the default lifecycle hooks");
    return ok ? 0 : 1;
}
