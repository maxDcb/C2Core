#include "../ListProcesses.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    ListProcesses module;
    std::vector<std::string> cmd = {"ps"};
    C2Message message;
    C2Message ret;

    ok &= expect(module.init(cmd, message) == 0, "init should accept process listing command");
    ok &= expect(message.instruction() == "ps", "instruction should be set");
    module.process(message, ret);
    ok &= expect(!ret.returnvalue().empty(), "process listing should produce output");

    return ok ? 0 : 1;
}
