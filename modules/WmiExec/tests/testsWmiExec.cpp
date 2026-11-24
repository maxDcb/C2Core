#include "../WmiExec.hpp"
#include "../../tests/TestHelpers.hpp"
#include "../../tests/local/MessageTestHelpers.hpp"

#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        WmiExec module;
        std::vector<std::string> cmd = {"wmiExec", "-u", "DOMAIN\\alice", "secret", "server01", "cmd.exe", "/c", "whoami"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "credential WMI form should be accepted");
        ok &= expect(message.instruction() == "wmiExec", "instruction should be set");
        const auto fields = splitPackedFields(message.cmd());
        ok &= expect(fields.size() == 4, "packed WMI credential parameters should contain four fields");
        if (fields.size() == 4)
        {
            ok &= expect(fields[0] == "DOMAIN", "domain should be packed");
            ok &= expect(fields[1] == "alice", "username should be packed");
            ok &= expect(fields[2] == "secret", "password should be packed");
            ok &= expect(fields[3] == "server01", "target should be packed");
        }
        ok &= expect(message.data() == "cmd.exe /c whoami", "command tail should be packed");
    }

    {
        WmiExec module;
        std::vector<std::string> cmd = {"wmiExec", "-n", "localhost", "cmd.exe", "/c", "whoami"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "no-credential WMI form should be accepted");
        ok &= expect(message.cmd() == "localhost", "target should be packed in cmd");
        ok &= expect(message.data() == "cmd.exe /c whoami", "no-credential command tail should be packed");
    }

    {
        WmiExec module;
        std::vector<std::string> cmd = {"wmiExec", "-u", "alice"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "incomplete credential WMI form should be rejected");
    }

    {
        WmiExec preparer;
        WmiExec executor;
        WmiExec receiver;
        std::vector<std::string> cmd = {"wmiExec", "-n", "localhost", "cmd.exe"};
        C2Message prepared;
        ok &= expect(preparer.init(cmd, prepared) == 0, "valid request can be prepared");
        C2Message request = roundTripMessage(prepared);
        request.set_cmd(std::string("a\0b", 3));
        C2Message executed;
        executor.process(request, executed);
        const C2Message received = roundTripMessage(executed);
#ifdef _WIN32
        ok &= expect(received.errorCode() == 11, "malformed request reports configuration error");
#else
        ok &= expect(received.errorCode() == 100, "Linux reports Windows-only execution");
#endif
        ok &= expect(received.returnvalue().empty(), "failed response carries no output");
        ok &= expect(received.instruction() == "wmiExec", "response preserves instruction");

        for (int code : {1,2,3,4,5,6,7,8,9,10,11,12,100})
        {
            C2Message codeOnly;
            codeOnly.set_errorCode(code);
            std::string error;
            receiver.errorCodeToMsg(roundTripMessage(codeOnly), error);
            ok &= expect(!error.empty(), "received error code has a stable message");
        }
        C2Message success;
        success.set_errorCode(0);
        std::string stale = "previous error";
        receiver.errorCodeToMsg(roundTripMessage(success), stale);
        ok &= expect(stale.empty(), "success clears an earlier error message");
    }

    return ok ? 0 : 1;
}
