#include "../CimExec.hpp"
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
        CimExec module;
        std::vector<std::string> cmd = {
            "cimExec", "-h", "localhost", "-n", "root/custom",
            "-c", "cmd.exe", "-a", "/c whoami", "-u", "DOMAIN\\alice", "-p", "secret"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "init should accept complete CIM parameters");
        ok &= expect(message.instruction() == "cimExec", "instruction should be set");

        const auto fields = splitPackedFields(message.cmd());
        ok &= expect(fields.size() == 6, "packed CIM parameters should contain six fields");
        if (fields.size() == 6)
        {
            ok &= expect(fields[0] == "localhost", "host should be packed");
            ok &= expect(fields[1] == "root/custom", "namespace should be packed");
            ok &= expect(fields[2] == "cmd.exe", "command should be packed");
            ok &= expect(fields[3] == "/c whoami", "arguments should be packed");
            ok &= expect(fields[4] == "DOMAIN\\alice", "username should be packed");
            ok &= expect(fields[5] == "secret", "password should be packed");
        }
    }

    {
        CimExec module;
        std::vector<std::string> cmd = {"cimExec", "-h", "localhost"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing command should be rejected");
        ok &= expect(!message.returnvalue().empty(), "missing command should explain the error");
    }

    {
        CimExec preparer;
        CimExec executor;
        CimExec receiver;
        std::vector<std::string> cmd = {"cimExec", "-h", "localhost", "-c", "cmd.exe"};
        C2Message prepared;
        ok &= expect(preparer.init(cmd, prepared) == 0, "valid request can be prepared");
        C2Message request = roundTripMessage(prepared);
        request.set_cmd(std::string("bad\0", 4));
        C2Message executed;
        executor.process(request, executed);
        const C2Message received = roundTripMessage(executed);
#ifdef _WIN32
        ok &= expect(received.errorCode() == 9, "malformed request reports configuration error");
#else
        ok &= expect(received.errorCode() == 10, "Linux reports Windows-only execution");
#endif
        ok &= expect(received.returnvalue().empty(), "failed response carries no output");
        ok &= expect(received.instruction() == "cimExec", "response preserves instruction");

        for (int code : {1,2,3,4,5,6,7,8,9,10,11,99})
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
