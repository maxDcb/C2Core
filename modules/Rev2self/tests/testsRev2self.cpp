#include "../Rev2self.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    Rev2self module;
    std::vector<std::string> cmd = {"rev2self"};
    C2Message message;

    bool ok = true;
    ok &= expect(module.init(cmd, message) == 0, "init should accept rev2self command");
    ok &= expect(message.instruction() == "rev2self", "instruction should be set");
    ok &= expect(message.cmd().empty(), "rev2self should pack an empty command");

    return ok ? 0 : 1;
}
