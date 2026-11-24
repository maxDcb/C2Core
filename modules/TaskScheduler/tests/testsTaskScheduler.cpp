#include "../TaskScheduler.hpp"
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
        TaskScheduler module;
        std::vector<std::string> cmd = {
            "taskScheduler", "-s", "server01", "-t", "UnitTask",
            "-c", "cmd.exe", "-a", "/c whoami", "-u", "DOMAIN\\alice",
            "-p", "secret", "--no-run", "--nocleanup"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "init should accept complete task parameters");
        ok &= expect(message.instruction() == "taskScheduler", "instruction should be set");

        const auto fields = splitPackedFields(message.cmd());
        ok &= expect(fields.size() == 8, "packed task parameters should contain eight fields");
        if (fields.size() == 8)
        {
            ok &= expect(fields[0] == "server01", "server should be packed");
            ok &= expect(fields[1] == "UnitTask", "task name should be packed");
            ok &= expect(fields[2] == "cmd.exe", "command should be packed");
            ok &= expect(fields[3] == "/c whoami", "arguments should be packed");
            ok &= expect(fields[4] == "DOMAIN\\alice", "username should be packed");
            ok &= expect(fields[5] == "secret", "password should be packed");
            ok &= expect(fields[6] == "1", "skip-run flag should be packed");
            ok &= expect(fields[7] == "0", "nocleanup flag should be packed");
        }
    }

    {
        TaskScheduler module;
        std::vector<std::string> cmd = {"taskScheduler", "-a", "/c whoami"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing command should be rejected");
        ok &= expect(!message.returnvalue().empty(), "missing command should explain the error");
    }

    {
        TaskScheduler preparer;
        TaskScheduler executor;
        TaskScheduler receiver;
        std::vector<std::string> cmd = {"taskScheduler", "-c", "cmd.exe"};
        C2Message prepared;
        ok &= expect(preparer.init(cmd, prepared) == 0, "valid request can be prepared");
        C2Message request = roundTripMessage(prepared);
        request.set_cmd(std::string("bad\0", 4));
        C2Message executed;
        executor.process(request, executed);
        const C2Message received = roundTripMessage(executed);
#ifdef _WIN32
        ok &= expect(received.errorCode() == 15, "malformed request reports configuration error");
#else
        ok &= expect(received.errorCode() == 16, "Linux reports Windows-only execution");
#endif
        ok &= expect(received.returnvalue().empty(), "failed response carries no output");
        ok &= expect(received.instruction() == "taskScheduler", "response preserves instruction");

        for (int code : {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16})
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
