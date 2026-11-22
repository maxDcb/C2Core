#include "../Shell.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace
{
    bool expectContains(const std::string& text, const std::string& needle, const std::string& message)
    {
        return test_helpers::expect(text.find(needle) != std::string::npos, message);
    }

    C2Message initShell(Shell& shell, std::vector<std::string> command, bool& ok)
    {
        C2Message message;
        ok &= test_helpers::expect(shell.init(command, message) == 0, command.front() + " init should succeed");
        return message;
    }

    C2Message runShellCommand(Shell& shell, std::vector<std::string> command, bool& ok)
    {
        C2Message message = initShell(shell, command, ok);
        C2Message ret;
        ok &= test_helpers::expect(shell.process(message, ret) == 0, message.cmd() + " process should succeed");
        ok &= test_helpers::expect(ret.instruction() == "shell", message.cmd() + " return instruction should be set");
        return ret;
    }

    std::vector<std::string> stateSetCommand()
    {
#ifdef _WIN32
        return {"shell", "set", "C2CORE_SHELL_STATE=alpha&", "echo", "c2core-state-set"};
#else
        return {"shell", "export", "C2CORE_SHELL_STATE=alpha;", "echo", "c2core-state-set"};
#endif
    }

    std::vector<std::string> stateReadCommand()
    {
#ifdef _WIN32
        return {"shell", "echo", "%C2CORE_SHELL_STATE%"};
#else
        return {"shell", "printf", "'%s\\n'", "\"$C2CORE_SHELL_STATE\""};
#endif
    }
}

int main()
{
    bool ok = true;

    {
        Shell shell;
        std::vector<std::string> command = {"shell"};
        C2Message message;
        ok &= test_helpers::expect(shell.init(command, message) == 0, "empty shell command init should succeed");
        ok &= test_helpers::expect(message.instruction() == "shell", "instruction should be set");
        ok &= test_helpers::expect(message.cmd().empty(), "empty shell command should not set a command payload");

        command = {"shell", "echo", "hello"};
        message = C2Message{};
        ok &= test_helpers::expect(shell.init(command, message) == 0, "positional command init should succeed");
        ok &= test_helpers::expect(message.cmd() == "echo hello", "positional command should be packed without trailing spaces");

        command = {"shell", "cmd", "/c", "echo", "hello"};
        message = C2Message{};
        ok &= test_helpers::expect(shell.init(command, message) == 0, "multi-token command init should succeed");
        ok &= test_helpers::expect(message.cmd() == "cmd /c echo hello", "multi-token command should preserve token order");

        C2Message ret;
        std::string errorMsg = "unchanged";
        ok &= test_helpers::expect(shell.followUp(ret) == 0, "followUp should be a no-op");
        ok &= test_helpers::expect(shell.errorCodeToMsg(ret, errorMsg) == 0, "errorCodeToMsg should be a no-op");
        ok &= test_helpers::expect(errorMsg.empty(), "success should clear an earlier error message");
    }

    {
        Shell shell;
        C2Message first = runShellCommand(shell, {"shell", "echo", "c2core-first-command"}, ok);
        ok &= test_helpers::expect(first.errorCode() == 0
            && first.returnvalue().find("c2core-first-command") != std::string::npos,
            "a first nonempty command should execute in the default shell");
        runShellCommand(shell, {"shell", "exit"}, ok);
    }

    {
        Shell shell;
        C2Message ret = runShellCommand(shell, {"shell"}, ok);
        ok &= test_helpers::expect(ret.errorCode() == 0, "shell start should set code zero");
        ok &= test_helpers::expect(ret.returnvalue() == "shell started", "empty command should start the persistent shell");

        ret = runShellCommand(shell, stateSetCommand(), ok);
        ok &= expectContains(ret.returnvalue(), "c2core-state-set", "first command should run in the persistent shell");

        ret = runShellCommand(shell, stateReadCommand(), ok);
        ok &= expectContains(ret.returnvalue(), "alpha", "state set by a previous command should persist");

        ret = runShellCommand(shell, {"shell", "echo", "c2core-second-command"}, ok);
        ok &= expectContains(ret.returnvalue(), "c2core-second-command", "a later command should still use the same shell");

        ret = runShellCommand(shell, {"shell", "exit"}, ok);
        ok &= test_helpers::expect(ret.returnvalue() == "shell terminated", "exit command should stop the shell");

        ret = runShellCommand(shell, {"shell"}, ok);
        ok &= test_helpers::expect(ret.returnvalue() == "shell started", "shell should be restartable after exit");

        ret = runShellCommand(shell, {"shell", "exit"}, ok);
        ok &= test_helpers::expect(ret.returnvalue() == "shell terminated", "second exit command should stop the restarted shell");
    }

    {
        Shell receiver;
        C2Message codeOnly;
        codeOnly.set_errorCode(1);
        std::string errorMsg;
        ok &= test_helpers::expect(receiver.errorCodeToMsg(codeOnly, errorMsg) == 0,
            "shell startup code should be translated");
        ok &= test_helpers::expect(errorMsg == "Failed to start shell.",
            "shell startup code should produce a stable message");
    }

    std::cout << (ok ? "[+]" : "[-]") << " shell tests" << std::endl;
    return ok ? 0 : 1;
}
