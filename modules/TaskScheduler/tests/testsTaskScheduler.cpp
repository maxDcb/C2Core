#include "../TaskScheduler.hpp"
#include "../../tests/TestHelpers.hpp"

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
        TaskScheduler module;
        C2Message ret;
        ret.set_errorCode(4);
        ret.set_returnvalue("connect failed");
        std::string error;

        ok &= expect(module.errorCodeToMsg(ret, error) == 0, "errorCodeToMsg should return success");
        ok &= expect(error == "connect failed", "errorCodeToMsg should expose process error text");
    }

    return ok ? 0 : 1;
}
