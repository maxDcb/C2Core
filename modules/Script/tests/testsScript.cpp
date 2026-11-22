#include "../Script.hpp"
#include "../../tests/TestHelpers.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

using namespace test_helpers;

namespace
{
    std::filesystem::path writeTempFileWithExtension(const std::string& stem,
                                                     const std::string& extension,
                                                     const std::string& content)
    {
        const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())
            + "_" + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
        const auto path = std::filesystem::temp_directory_path() / (stem + "_" + suffix + extension);
        std::ofstream out(path, std::ios::binary);
        out << content;
        return path;
    }

    bool expectContains(const std::string& text, const std::string& needle, const std::string& message)
    {
        return expect(text.find(needle) != std::string::npos, message);
    }
}

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

#ifdef _WIN32
    {
        const auto script = writeTempFileWithExtension(
            "c2core_script_exec",
            ".cmd",
            "@echo off\r\n"
            "echo script-stdout\r\n"
            "echo script-stderr 1>&2\r\n");
        Script module;
        std::vector<std::string> cmd = {"script", script.string()};
        C2Message message;
        C2Message ret;

        ok &= expect(module.init(cmd, message) == 0, "Windows cmd script should be accepted");
        ok &= expect(module.process(message, ret) == 0, "Windows cmd script should execute");
        ok &= expect(ret.instruction() == "script", "Windows cmd script should preserve instruction");
        ok &= expect(ret.errorCode() == 0, "successful Windows script should set code zero");
        ok &= expectContains(ret.returnvalue(), "script-stdout", "Windows cmd script should capture stdout");
        ok &= expectContains(ret.returnvalue(), "script-stderr", "Windows cmd script should capture stderr");
        std::filesystem::remove(script);
    }

    {
        const auto script = writeTempFileWithExtension(
            "c2core_script_unsupported",
            ".ps1",
            "Write-Output unsupported\r\n");
        Script module;
        std::vector<std::string> cmd = {"script", script.string()};
        C2Message message;
        C2Message ret;

        ok &= expect(module.init(cmd, message) == 0, "unsupported Windows script extension should still be transportable");
        ok &= expect(module.process(message, ret) == 0, "unsupported Windows script extension should return cleanly");
        ok &= expect(ret.errorCode() == 2, "unsupported Windows script extension should set its defined code");
        ok &= expect(ret.returnvalue().empty(), "unsupported Windows script should not carry error text as output");
        std::string errorMsg;
        ok &= expect(module.errorCodeToMsg(ret, errorMsg) == 0, "unsupported Windows script extension should map error text");
        ok &= expect(errorMsg == "Unsupported script type on Windows. Use .bat or .cmd.",
            "unsupported Windows script error text should come from its code");
        std::filesystem::remove(script);
    }
#endif

    return ok ? 0 : 1;
}
