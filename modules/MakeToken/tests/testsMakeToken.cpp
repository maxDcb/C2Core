#include "../MakeToken.hpp"
#include "../../tests/TestHelpers.hpp"

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
        MakeToken module;
        C2Message message;
        C2Message ret;
        message.set_cmd("broken");
        module.process(message, ret);
        ok &= expect(ret.errorCode() == 1, "invalid packed credential should set an error");
    }

    return ok ? 0 : 1;
}
