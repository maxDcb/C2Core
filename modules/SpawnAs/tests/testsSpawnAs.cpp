#include "../SpawnAs.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        SpawnAs module;
        std::vector<std::string> cmd = {
            "spawnAs", "-d", ".", "--netonly", "--no-profile",
            "alice", "secret", "--", "cmd.exe", "/c", "whoami"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "spawnAs should accept explicit options and command separator");
        ok &= expect(message.instruction() == "spawnAs", "instruction should be set");
        ok &= expect(message.data() == "cmd.exe /c whoami", "command should be packed in data");

        const auto credentials = splitPackedFields(message.cmd());
        ok &= expect(credentials.size() == 3, "packed spawnAs credentials should contain three fields");
        if (credentials.size() == 3)
        {
            ok &= expect(credentials[0] == ".", "domain should be packed");
            ok &= expect(credentials[1] == "alice", "username should be packed");
            ok &= expect(credentials[2] == "secret", "password should be packed");
        }

        const auto options = splitPackedFields(message.args());
        ok &= expect(options.size() == 3, "packed spawnAs options should contain three fields");
        if (options.size() == 3)
        {
            ok &= expect(options[0] == "9", "netonly logon type should be packed");
            ok &= expect(options[1] == "0", "no-profile flag should be packed");
            ok &= expect(options[2] == "0", "hidden-window default should be packed");
        }
    }

    {
        SpawnAs module;
        std::vector<std::string> cmd = {"spawnAs", "--logon-type", "99", "alice", "secret", "--", "cmd.exe"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "unsupported logon type should be rejected");
        ok &= expect(!message.returnvalue().empty(), "unsupported logon type should explain the error");
    }

    {
        SpawnAs module;
        std::vector<std::string> cmd = {"spawnAs", "alice", "secret"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing command should be rejected");
    }

    return ok ? 0 : 1;
}
