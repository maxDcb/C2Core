#include "../AssemblyExec.hpp"
#include "../../tests/TestHelpers.hpp"

#include <filesystem>
#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        AssemblyExec module;
        std::vector<std::string> cmd = {"assemblyExec", "thread"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "thread mode should be handled locally");
        ok &= expect(message.returnvalue() == "thread mode.\n", "thread mode should report selected mode");
    }

    {
        AssemblyExec module;
        std::vector<std::string> cmd = {"assemblyExec", "-r", "missing.bin"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing raw shellcode file should be rejected");
        ok &= expect(message.returnvalue().find("Couldn't open file") != std::string::npos, "missing file error should mention open failure");
    }

    {
        const auto raw = writeTempFile("c2core_assembly_raw.bin", "raw-bytes");
        AssemblyExec module;
        std::vector<std::string> cmd = {"assemblyExec", "-r", raw.string()};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "existing raw shellcode file should be accepted");
        ok &= expect(message.instruction() == "assemblyExec", "instruction should be set");
        ok &= expect(message.inputfile() == raw.string(), "input file should be packed");
        ok &= expect(message.data() == "raw-bytes", "raw bytes should be packed");
        std::filesystem::remove(raw);
    }

    return ok ? 0 : 1;
}
