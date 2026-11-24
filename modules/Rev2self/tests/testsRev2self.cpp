#include "../Rev2self.hpp"
#include "../../tests/TestHelpers.hpp"
#include "../../tests/local/MessageTestHelpers.hpp"

#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    Rev2self module;
    std::vector<std::string> cmd = {"rev2self"};
    C2Message message;

    bool ok = true;
    ok &= expect(module.init(cmd, message) == 0, "init should accept rev2self command");
    ok &= expect(message.instruction() == "rev2self", "instruction should be set");
    ok &= expect(message.cmd().empty(), "rev2self should pack an empty command");

    std::vector<std::string> invalidCommand = {"rev2self", "extra"};
    C2Message invalid;
    ok &= expect(module.init(invalidCommand, invalid) == -1, "extra arguments are rejected");

    Rev2self executor;
    Rev2self receiver;
    C2Message request = roundTripMessage(message);
    C2Message executed;
    executor.process(request, executed);
    const C2Message received = roundTripMessage(executed);
#ifdef _WIN32
    ok &= expect(received.errorCode() == 0 && received.returnvalue() == "Reverted to self.\n",
        "Windows reverts the test process token with explicit success status");
#else
    ok &= expect(received.errorCode() == 2 && received.returnvalue().empty(),
        "Linux reports unsupported execution without response text");
#endif
    for (int code = 1; code <= 2; ++code)
    {
        C2Message codeOnly;
        codeOnly.set_errorCode(code);
        std::string error;
        receiver.errorCodeToMsg(roundTripMessage(codeOnly), error);
        ok &= expect(!error.empty(), "received rev2self code has a stable message");
    }
    C2Message success;
    success.set_errorCode(0);
    std::string stale = "old error";
    receiver.errorCodeToMsg(roundTripMessage(success), stale);
    ok &= expect(stale.empty(), "success clears an earlier error message");

    return ok ? 0 : 1;
}
