#include "../WinRM.hpp"
#include "../../tests/TestHelpers.hpp"
#include "../../tests/local/MessageTestHelpers.hpp"

#include <iostream>
#include <memory>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        WinRM module;
        std::vector<std::string> cmd = {"winRm", "-n", "http://localhost:5985/wsman", "whoami.exe", "/all"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "init should accept no-credential WinRM command");
        ok &= expect(message.instruction() == "winRm", "instruction should be set");
        ok &= expect(message.cmd() == "http://localhost:5985/wsman", "target should be packed in cmd");
        ok &= expect(message.data() == "whoami.exe /all", "command tail should be packed in data");
    }

    {
        WinRM module;
        std::vector<std::string> cmd = {"winRm", "-u", "DOMAIN\\alice", "secret", "http://server:5985/wsman", "dir", "C:\\"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "init should accept credential WinRM command");
        const auto fields = splitPackedFields(message.cmd());
        ok &= expect(fields.size() == 4, "packed WinRM credential parameters should contain four fields");
        if (fields.size() == 4)
        {
            ok &= expect(fields[0] == "DOMAIN", "domain should be packed");
            ok &= expect(fields[1] == "alice", "username should be packed");
            ok &= expect(fields[2] == "secret", "password should be packed");
            ok &= expect(fields[3] == "http://server:5985/wsman", "target should be packed");
        }
        ok &= expect(message.data() == "dir C:\\", "credential command tail should be packed in data");
    }

    {
        WinRM module;
        std::vector<std::string> cmd = {"winRm", "-u", "alice"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "incomplete credential command should be rejected");
    }

    {
        WinRM preparer;
        WinRM executor;
        WinRM receiver;
        std::vector<std::string> cmd = {"winRm", "-n", "http://localhost:5985/wsman", "whoami.exe"};
        C2Message prepared;
        ok &= expect(preparer.init(cmd, prepared) == 0, "valid request can be prepared");
        C2Message request = roundTripMessage(prepared);
        request.set_cmd(std::string("a\0b", 3));
        C2Message executed;
        executor.process(request, executed);
        const C2Message received = roundTripMessage(executed);
#ifdef _WIN32
        ok &= expect(received.errorCode() == 1, "malformed WinRM request reports configuration error");
#else
        ok &= expect(received.errorCode() == 7, "Linux reports Windows-only execution");
#endif
        ok &= expect(received.returnvalue().empty(), "failed WinRM response carries no output");
        ok &= expect(received.instruction() == "winRm", "response preserves instruction");

        for (int code = 1; code <= 9; ++code)
        {
            C2Message codeOnly;
            codeOnly.set_errorCode(code);
            std::string error;
            receiver.errorCodeToMsg(roundTripMessage(codeOnly), error);
            ok &= expect(!error.empty(), "received WinRM error code has a stable message");
        }
        C2Message success;
        success.set_errorCode(0);
        std::string stale = "previous error";
        receiver.errorCodeToMsg(roundTripMessage(success), stale);
        ok &= expect(stale.empty(), "success clears an earlier error message");
    }

    return ok ? 0 : 1;
}
