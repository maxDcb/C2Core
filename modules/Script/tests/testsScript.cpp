#include "../Script.hpp"
#include "../../tests/TestHelpers.hpp"

#include <filesystem>
#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        Script module;
        std::vector<std::string> cmd = {"script"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing script path should be rejected");
    }

    {
        Script module;
        std::vector<std::string> cmd = {"script", "missing-script"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "nonexistent script should be rejected");
        ok &= expect(message.returnvalue().find("Fail to open file") != std::string::npos, "nonexistent script error should mention open failure");
    }

    {
        const auto script = writeTempFile("c2core_script", "echo script-test");
        Script module;
        std::vector<std::string> cmd = {"script", script.string()};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "existing script should be accepted");
        ok &= expect(message.instruction() == "script", "instruction should be set");
        ok &= expect(message.inputfile() == script.string(), "input file should be packed");
        ok &= expect(message.data() == "echo script-test", "script content should be packed");
        std::filesystem::remove(script);
    }

    return ok ? 0 : 1;
}
