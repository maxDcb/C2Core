#include "../Evasion.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        Evasion module;
        std::vector<std::string> cmd = {"evasion", "CheckHooks"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "CheckHooks should be accepted");
        ok &= expect(message.instruction() == "evasion", "instruction should be set");
        ok &= expect(message.cmd() == "1", "CheckHooks command id should be packed");
    }

    {
        Evasion module;
        std::vector<std::string> cmd = {"evasion", "ReadMemory", "0x1234", "16"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "ReadMemory should accept address and size");
        ok &= expect(message.cmd() == "7", "ReadMemory command id should be packed");
        ok &= expect(message.data() == "0x1234", "ReadMemory address should be packed");
        ok &= expect(message.args() == "16", "ReadMemory size should be packed");
    }

    {
        Evasion module;
        std::vector<std::string> cmd = {"evasion", "ReadMemory", "0x1234"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "ReadMemory should reject missing size");
    }

    return ok ? 0 : 1;
}
