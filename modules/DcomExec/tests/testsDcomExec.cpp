#include "../DcomExec.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <memory>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        DcomExec module;
        std::vector<std::string> cmd = {
            "dcomExec", "-h", "server01", "-k", "HOST/server01.domain",
            "-u", "DOMAIN\\alice", "-p", "secret", "-c", "cmd.exe",
            "-a", "/c whoami", "-w", "C:\\Windows"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "init should accept complete DCOM parameters");
        ok &= expect(message.instruction() == "dcomExec", "instruction should be set");

        const auto fields = splitPackedFields(message.cmd());
        ok &= expect(fields.size() == 9, "packed DCOM parameters should contain nine fields");
        if (fields.size() == 9)
        {
            ok &= expect(fields[0] == "server01", "host should be packed");
            ok &= expect(fields[2] == "cmd.exe", "command should be packed");
            ok &= expect(fields[3] == "/c whoami", "arguments should be packed");
            ok &= expect(fields[4] == "C:\\Windows", "working directory should be packed");
            ok &= expect(fields[5] == "HOST/server01.domain", "SPN should be packed");
            ok &= expect(fields[6] == "DOMAIN\\alice", "username should be packed");
            ok &= expect(fields[7] == "secret", "password should be packed");
            ok &= expect(fields[8] == "0", "no-password flag should be packed");
        }
    }

    {
        DcomExec module;
        std::vector<std::string> cmd = {"dcomExec", "-h", "server01", "-p", "secret", "-c", "cmd.exe"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "password without username should be rejected");
        ok &= expect(!message.returnvalue().empty(), "credential validation should explain the error");
    }

    {
        DcomExec module;
        C2Message ret;
        ret.set_errorCode(4);
        ret.set_returnvalue("dcom failed");
        std::string error;

        ok &= expect(module.errorCodeToMsg(ret, error) == 0, "errorCodeToMsg should return success");
        ok &= expect(error.find("dcom failed") != std::string::npos, "errorCodeToMsg should expose process error text");
    }

    return ok ? 0 : 1;
}
