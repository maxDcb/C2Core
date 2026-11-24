#include "../MakeToken.hpp"
#include "../../tests/TestHelpers.hpp"
#include "../../tests/local/MessageTestHelpers.hpp"

#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        MakeToken module;
        std::vector<std::string> cmd = {"makeToken", "DOMAIN\\alice", "secret"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "domain credential form should be accepted");
        ok &= expect(message.instruction() == "makeToken", "instruction should be set");
        ok &= expect(message.cmd() == "DOMAIN;alice;secret", "domain credential should be packed");
    }

    {
        MakeToken module;
        std::vector<std::string> cmd = {"makeToken", "alice", "secret"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "local credential form should be accepted");
        ok &= expect(message.cmd() == ".;alice;secret", "local credential should default to dot domain");
    }

    {
        MakeToken module;
        std::vector<std::string> cmd = {"makeToken", "alice"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing password should be rejected");
    }

    {
        MakeToken executor;
        MakeToken receiver;
        C2Message prepared;
        prepared.set_instruction("makeToken");
        prepared.set_cmd("broken");
        C2Message request = roundTripMessage(prepared);
        C2Message executed;
        executor.process(request, executed);
        const C2Message received = roundTripMessage(executed);
        ok &= expect(received.errorCode() == 1, "invalid packed credential sets an error");
        ok &= expect(received.returnvalue().empty(), "failed token request has no output");
        ok &= expect(received.instruction() == "makeToken", "response preserves instruction");
        for (int code = 1; code <= 4; ++code)
        {
            C2Message codeOnly;
            codeOnly.set_errorCode(code);
            std::string error;
            receiver.errorCodeToMsg(roundTripMessage(codeOnly), error);
            ok &= expect(!error.empty(), "received token error code has a stable message");
        }
        C2Message success;
        success.set_errorCode(0);
        std::string stale = "previous error";
        receiver.errorCodeToMsg(roundTripMessage(success), stale);
        ok &= expect(stale.empty(), "success clears an earlier error message");
    }

    return ok ? 0 : 1;
}
