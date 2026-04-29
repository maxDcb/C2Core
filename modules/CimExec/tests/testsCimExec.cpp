#include "../CimExec.hpp"
#include "../../tests/TestHelpers.hpp"

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
        CimExec module;
        C2Message ret;
        ret.set_errorCode(4);
        ret.set_returnvalue("session failed");
        std::string error;

        ok &= expect(module.errorCodeToMsg(ret, error) == 0, "errorCodeToMsg should return success");
        ok &= expect(error == "session failed", "errorCodeToMsg should expose process error text");
    }

    return ok ? 0 : 1;
}
