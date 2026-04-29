#include "../StealToken.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        StealToken module;
        std::vector<std::string> cmd = {"stealToken", "1234"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "numeric pid should be accepted");
        ok &= expect(message.instruction() == "stealToken", "instruction should be set");
        ok &= expect(message.pid() == 1234, "pid should be packed");
    }

    {
        StealToken module;
        std::vector<std::string> cmd = {"stealToken", "not-a-pid"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "non-numeric pid should be rejected");
    }

    return ok ? 0 : 1;
}
