#include "../KeyLogger.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        KeyLogger module;
        std::vector<std::string> cmd = {"keyLogger", "start"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "start should be accepted");
        ok &= expect(message.instruction() == "keyLogger", "instruction should be set");
        ok &= expect(message.args() == "start", "start action should be packed");
    }

    {
        KeyLogger module;
        C2Message follow;
        follow.set_data("abc");
        module.followUp(follow);

        std::vector<std::string> cmd = {"keyLogger", "dump"};
        C2Message message;
        ok &= expect(module.init(cmd, message) == -1, "dump should be handled locally");
        ok &= expect(message.returnvalue().find("abc") != std::string::npos, "dump should expose buffered keys");
    }

    {
        KeyLogger module;
        std::vector<std::string> cmd = {"keyLogger", "invalid"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "unknown keylogger action should be rejected");
    }

    return ok ? 0 : 1;
}
