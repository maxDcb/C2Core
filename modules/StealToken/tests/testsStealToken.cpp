#include "../StealToken.hpp"
#include "../../tests/TestHelpers.hpp"
#include "../../tests/local/MessageTestHelpers.hpp"

#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        StealToken module;
        std::vector<std::string> cmd = {"stealToken", "1234"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "numeric pid should be accepted");
        ok &= expect(message.instruction() == "stealToken", "instruction should be set");
        ok &= expect(message.pid() == 1234, "pid should be packed");
    }

    {
        StealToken module;
        std::vector<std::string> cmd = {"stealToken", "not-a-pid"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "non-numeric pid should be rejected");
    }

    {
        StealToken preparer;
        C2Message invalid;
        std::vector<std::string> command = {"stealToken", "12bad"};
        ok &= expect(preparer.init(command, invalid) == -1, "trailing text in PID is rejected");
        command = {"stealToken", "999999999999999999999"};
        ok &= expect(preparer.init(command, invalid) == -1, "out-of-range PID is rejected");
    }
    {
        StealToken executor;
        StealToken receiver;
        C2Message prepared;
        prepared.set_instruction("stealToken");
        prepared.set_pid(0);
        C2Message request = roundTripMessage(prepared);
        C2Message executed;
        executor.process(request, executed);
        const C2Message received = roundTripMessage(executed);
        ok &= expect(received.errorCode() == 1 && received.returnvalue().empty(),
            "invalid transported PID fails without output");
        ok &= expect(received.instruction() == "stealToken", "response preserves instruction");
        C2Message absentRequest;
        absentRequest.set_instruction("stealToken");
        absentRequest.set_pid(2147483647);
        C2Message absentResponse;
        executor.process(absentRequest, absentResponse);
        const C2Message absentReceived = roundTripMessage(absentResponse);
#ifdef _WIN32
        ok &= expect(absentReceived.errorCode() == 2 && absentReceived.returnvalue().empty(),
            "an absent target PID reports a code-only process-open failure");
#else
        ok &= expect(absentReceived.errorCode() == 6 && absentReceived.returnvalue().empty(),
            "Linux reports unsupported token access");
#endif
        for (int code = 1; code <= 6; ++code)
        {
            C2Message codeOnly;
            codeOnly.set_errorCode(code);
            std::string error;
            receiver.errorCodeToMsg(roundTripMessage(codeOnly), error);
            ok &= expect(!error.empty(), "received stealToken error code has a stable message");
        }
        C2Message success;
        success.set_errorCode(0);
        std::string stale = "previous error";
        receiver.errorCodeToMsg(roundTripMessage(success), stale);
        ok &= expect(stale.empty(), "success clears an earlier error message");
    }

    return ok ? 0 : 1;
}
