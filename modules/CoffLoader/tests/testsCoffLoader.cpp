#include "../CoffLoader.hpp"
#include "../../tests/TestHelpers.hpp"

#include <filesystem>
#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        CoffLoader module;
        std::vector<std::string> cmd = {"coffLoader", "missing.o", "go"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing COFF file should be rejected");
        ok &= expect(message.returnvalue().find("Couldn't open file") != std::string::npos, "missing COFF error should mention open failure");
    }

    {
        const auto coff = writeTempFile("c2core_dummy.o", "coff-bytes");
        CoffLoader module;
        std::vector<std::string> cmd = {"coffLoader", coff.string(), "go", "Zs", "c:\\", "0"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "existing COFF file should be accepted");
        ok &= expect(message.instruction() == "coffLoader", "instruction should be set");
        ok &= expect(message.inputfile() == coff.string(), "input file should be packed");
        ok &= expect(message.cmd() == "go", "function name should be packed");
        ok &= expect(message.args() == "Zs c:\\ 0", "COFF arguments should be packed");
        ok &= expect(message.data() == "coff-bytes", "COFF bytes should be packed");
        std::filesystem::remove(coff);
    }

    return ok ? 0 : 1;
}
