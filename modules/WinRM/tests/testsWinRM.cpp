#include "../WinRM.hpp"
#include "../../tests/TestHelpers.hpp"

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
        WinRM module;
        C2Message ret;
        ret.set_errorCode(2);
        ret.set_returnvalue("wsman failed");
        std::string error;

        ok &= expect(module.errorCodeToMsg(ret, error) == 0, "errorCodeToMsg should return success");
        ok &= expect(error == "wsman failed", "errorCodeToMsg should expose process error text");
    }

    return ok ? 0 : 1;
}
