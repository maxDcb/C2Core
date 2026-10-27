#include "../Run.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace
{
    bool expectContains(const std::string& text, const std::string& needle, const std::string& message)
    {
        return test_helpers::expect(text.find(needle) != std::string::npos, message);
    }

    bool expectErrorMessage(Run& module, int errorCode, const std::string& expected, const std::string& label)
    {
        C2Message message;
        message.set_errorCode(errorCode);
        std::string error;
        bool ok = true;
        ok &= test_helpers::expect(module.errorCodeToMsg(message, error) == 0, label + ": errorCodeToMsg should return 0");
        ok &= test_helpers::expect(error == expected, label + ": error message should match");
        return ok;
    }
}

int main()
{
    bool ok = true;
    Run module;

    {
        std::vector<std::string> command = {"run"};
        C2Message message;
        ok &= test_helpers::expect(module.init(command, message) == -1, "missing command should be rejected");
        ok &= test_helpers::expect(message.instruction().empty(), "missing command should not set an instruction");
        ok &= test_helpers::expect(message.cmd().empty(), "missing command should not set a command");
    }

    {
#ifdef _WIN32
        std::vector<std::string> command = {"run", "cmd.exe", "/c", "echo", "hello"};
        const std::string expectedCmd = "cmd.exe /c echo hello ";
#else
        std::vector<std::string> command = {"run", "echo", "hello"};
        const std::string expectedCmd = "echo hello ";
#endif
        C2Message message;
        ok &= test_helpers::expect(module.init(command, message) == 0, "simple command init should succeed");
        ok &= test_helpers::expect(message.instruction() == "run", "instruction should be set");
        ok &= test_helpers::expect(message.cmd() == expectedCmd, "command should be packed using the current token join logic");
    }

    {
#ifdef _WIN32
        std::vector<std::string> command = {"run", "cmd.exe", "/c", "echo", "hello", "world"};
#else
        std::vector<std::string> command = {"run", "printf", "'hello world\\n'"};
#endif
        C2Message message;
        ok &= test_helpers::expect(module.init(command, message) == 0, "success command init should succeed");

        C2Message ret;
        ok &= test_helpers::expect(module.process(message, ret) == 0, "success command process should succeed");
        ok &= test_helpers::expect(ret.instruction() == "run", "success command should keep the module instruction");
        ok &= test_helpers::expect(ret.cmd() == message.cmd(), "success command should echo the executed command");
        ok &= test_helpers::expect(ret.errorCode() == -1, "success command should not set an error code");
        ok &= expectContains(ret.returnvalue(), "hello", "success command should capture stdout");
        ok &= expectContains(ret.returnvalue(), "world", "success command should preserve multi-token output");
    }

    {
#ifdef _WIN32
        std::vector<std::string> command = {"run", "cmd.exe", "/c", "echo", "out", "&", "echo", "err", "1>&2"};
#else
        std::vector<std::string> command = {"run", "sh", "-c", "\"printf 'out\\n'; printf 'err\\n' 1>&2\""};
#endif
        C2Message message;
        ok &= test_helpers::expect(module.init(command, message) == 0, "stdout/stderr command init should succeed");

        C2Message ret;
        ok &= test_helpers::expect(module.process(message, ret) == 0, "stdout/stderr command process should succeed");
        ok &= expectContains(ret.returnvalue(), "out", "stdout/stderr command should capture stdout");
#ifdef _WIN32
        ok &= expectContains(ret.returnvalue(), "Stderr:", "Windows output should label stderr separately");
        ok &= expectContains(ret.returnvalue(), "err", "Windows output should capture stderr");
#else
        ok &= test_helpers::expect(ret.errorCode() == -1, "Linux shell stderr should not become a module error");
        ok &= expectContains(ret.returnvalue(), "err", "Linux shell should capture stderr");
#endif
    }

#ifndef _WIN32
    {
        C2Message message;
        message.set_instruction("run");
        message.set_cmd("python3 -c 'import sys; sys.stdout.write(\"BEGIN|\" + \"A\"*110000 + \"|END\")'");
        C2Message ret;
        ok &= test_helpers::expect(module.process(message, ret) == 0, "large command should execute");
        ok &= test_helpers::expect(ret.errorCode() == -1, "large command should succeed");
        ok &= test_helpers::expect(ret.returnvalue().size() == 110010, "large output should remain complete");
        ok &= test_helpers::expect(ret.returnvalue().rfind("BEGIN|", 0) == 0
            && ret.returnvalue().substr(ret.returnvalue().size() - 4) == "|END",
            "large output boundaries should remain intact");
    }

    {
        C2Message message;
        message.set_instruction("run");
        message.set_cmd("python3 -c 'raise SystemExit(7)'");
        C2Message ret;
        ok &= test_helpers::expect(module.process(message, ret) == 0, "failed command should return a result");
        ok &= test_helpers::expect(ret.errorCode() == 3, "nonzero exit must mark command failed");
        std::string error;
        module.errorCodeToMsg(ret, error);
        ok &= expectContains(error, "non-zero status", "exit failure should be reported");
    }
#endif

#ifdef _WIN32
    {
        C2Message message;
        message.set_instruction("run");
        message.set_cmd("definitely_missing_c2_run_program.exe");

        C2Message ret;
        ok &= test_helpers::expect(module.process(message, ret) == 0, "startup failure should return through C2Message");
        ok &= test_helpers::expect(ret.instruction() == "run", "startup failure should preserve the module instruction");
        ok &= test_helpers::expect(ret.errorCode() == 1, "startup failure should use error code 1");
        ok &= test_helpers::expect(ret.returnvalue().empty(), "startup failure should not fake process output");

        std::string error;
        ok &= test_helpers::expect(module.errorCodeToMsg(ret, error) == 0, "startup failure should map to an error message");
        ok &= test_helpers::expect(error == "Process failed to start.", "startup failure should expose the start failure message");
    }
#endif

    ok &= expectErrorMessage(module, 99, "Unknown error: code 99", "unknown error code");

    {
        C2Message message;
        message.set_errorCode(0);
        std::string error = "unchanged";
        ok &= test_helpers::expect(module.errorCodeToMsg(message, error) == 0, "zero error code should return 0");
        ok &= test_helpers::expect(error == "unchanged", "zero error code should leave the error message unchanged");
    }

    std::cout << (ok ? "[+]" : "[-]") << " run tests" << std::endl;
    return ok ? 0 : 1;
}
