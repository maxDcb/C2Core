#include "../ScreenShot.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    ScreenShot module;
    std::vector<std::string> cmd = {"screenShot"};
    C2Message message;

    bool ok = true;
    ok &= expect(module.init(cmd, message) == 0, "init should accept screenshot command");
    ok &= expect(message.instruction() == "screenShot", "instruction should be set");

    return ok ? 0 : 1;
}
