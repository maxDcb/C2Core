#include "../WmiExec.hpp"
#include "../../tests/TestHelpers.hpp"

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
        WmiExec module;
        C2Message ret;
        ret.set_errorCode(4);
        ret.set_returnvalue("connect failed");
        std::string error;

        ok &= expect(module.errorCodeToMsg(ret, error) == 0, "errorCodeToMsg should return success");
        ok &= expect(error == "connect failed", "errorCodeToMsg should expose process error text");
    }

    return ok ? 0 : 1;
}
