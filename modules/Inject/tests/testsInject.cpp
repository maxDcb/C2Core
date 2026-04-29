#include "../Inject.hpp"
#include "../../tests/TestHelpers.hpp"

#include <filesystem>
#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        Inject module;
        std::vector<std::string> cmd = {"inject", "-r", "missing.bin", "1234"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing raw shellcode file should be rejected");
        ok &= expect(message.returnvalue().find("Couldn't open file") != std::string::npos, "missing file error should mention open failure");
    }

    {
        Inject module;
        std::vector<std::string> cmd = {"inject", "-r", "payload.bin", "not-a-pid"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "non-numeric pid should be rejected");
        ok &= expect(message.returnvalue().find("Pid must be an integer") != std::string::npos, "pid error should explain the failure");
    }

    {
        const auto raw = writeTempFile("c2core_inject_raw.bin", "raw-bytes");
        Inject module;
        std::vector<std::string> cmd = {"inject", "-r", raw.string(), "-1"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "existing raw shellcode file should be accepted");
        ok &= expect(message.instruction() == "inject", "instruction should be set");
        ok &= expect(message.pid() == -1, "pid should be packed");
        ok &= expect(message.inputfile() == raw.string(), "input file should be packed");
        ok &= expect(message.data() == "raw-bytes", "raw bytes should be packed");
        std::filesystem::remove(raw);
    }

    return ok ? 0 : 1;
}
