#include "../Powershell.hpp"
#include "../../tests/TestHelpers.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

using namespace test_helpers;

namespace
{
bool expectBaseMessage(const C2Message& message,
                       const std::string& expectedCmd,
                       const std::string& label)
{
    bool ok = true;
    ok &= expect(message.instruction() == "powershell", label + ": instruction should be set");
    ok &= expect(message.cmd() == expectedCmd, label + ": command tail should be packed");
    return ok;
}

bool expectContains(const std::string& text, const std::string& needle, const std::string& label)
{
    return expect(text.find(needle) != std::string::npos, label);
}
}

int main()
{
    bool ok = true;

    {
        Powershell module;
        std::vector<std::string> cmd = {"powershell"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing command should be rejected");
    }

    {
        Powershell module;
        std::vector<std::string> cmd = {"powershell", "Write-Output", "hello"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "plain command should be accepted");
        ok &= expectBaseMessage(message, "Write-Output hello ", "plain command");
        ok &= expect(message.data().empty(), "plain command should not set script data");
        ok &= expect(message.inputfile().empty(), "plain command should not set an input file");
    }

    {
        Powershell module;
        std::vector<std::string> cmd = {"powershell", "-i", "missing.ps1"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing import script should be rejected");
        ok &= expectContains(message.returnvalue(), "Couldn't open file", "missing import script should explain the file error");
    }

    {
        Powershell module;
        std::vector<std::string> cmd = {"powershell", "-s", "missing.ps1"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing run script should be rejected");
        ok &= expectContains(message.returnvalue(), "Couldn't open file", "missing run script should explain the file error");
    }

    {
        const auto script = writeTempFile("c2core_powershell_import.ps1", "function Invoke-C2CoreTest { Write-Output \"import-ok\" }\n");
        Powershell module;
        std::vector<std::string> cmd = {"powershell", "-i", script.string()};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "existing import script should be accepted");
        ok &= expectBaseMessage(message, "-i " + script.string() + " ", "import script");
        ok &= expect(message.inputfile() == script.string(), "import script should pack input file");
        ok &= expectContains(message.data(), "New-Module -ScriptBlock", "import script should be wrapped in New-Module");
        ok &= expectContains(message.data(), "Invoke-C2CoreTest", "import script should include script content");
        ok &= expectContains(message.data(), "Export-ModuleMember -Function * -Alias *;};", "import script should export module members");
        std::filesystem::remove(script);
    }

    {
        const auto script = writeTempFile("c2core_powershell_script.ps1", "Write-Output \"script-ok\"\n");
        Powershell module;
        std::vector<std::string> cmd = {"powershell", "-s", script.string()};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "existing run script should be accepted");
        ok &= expectBaseMessage(message, "-s " + script.string() + " ", "run script");
        ok &= expect(message.inputfile() == script.string(), "run script should pack input file");
        ok &= expectContains(message.data(), "Invoke-Command -ScriptBlock", "run script should be wrapped in Invoke-Command");
        ok &= expectContains(message.data(), "script-ok", "run script should include script content");
        std::filesystem::remove(script);
    }

    {
        Powershell module;
        C2Message message;
        message.set_instruction("powershell");
        message.set_cmd("-s missing-payload.ps1 ");
        C2Message retMessage;

        ok &= expect(module.process(message, retMessage) == 0, "script command without payload should process");
        ok &= expect(retMessage.instruction() == "powershell", "script command without payload should preserve instruction");
        ok &= expect(retMessage.cmd() == message.cmd(), "script command without payload should preserve command");
        ok &= expectContains(retMessage.returnvalue(), "Missing PowerShell script payload", "script command without payload should explain failure");
    }

#if defined(__linux__) && defined(C2CORE_BUILD_TESTS)
    {
        Powershell module;
        C2Message message;
        message.set_instruction("powershell");
        message.set_cmd("-s testScript.ps1 ");
        message.set_data("Invoke-Command -ScriptBlock  {\nWrite-Output \"script-process-ok\"\n};");
        C2Message retMessage;

        ok &= expect(module.process(message, retMessage) == 0, "script payload should process");
        ok &= expect(retMessage.instruction() == "powershell", "script payload should preserve instruction");
        ok &= expect(retMessage.cmd() == message.cmd(), "script payload should preserve display command");
        ok &= expectContains(retMessage.returnvalue(), "script-process-ok", "script payload should be the executed command");
        ok &= expect(retMessage.returnvalue().find("-s testScript.ps1") == std::string::npos, "script payload should not execute the -s display command");
    }
#endif

#ifdef _WIN32
    {
        Powershell module;
        std::vector<std::string> cmd = {"powershell", "Write-Output", "\"c2core-powershell-exec\""};
        C2Message message;
        C2Message retMessage;

        ok &= expect(module.init(cmd, message) == 0, "execution command should be accepted");
        ok &= expect(module.process(message, retMessage) == 0, "execution command should process");
        ok &= expectContains(retMessage.returnvalue(), "c2core-powershell-exec", "execution output should be captured");
        ok &= expect(retMessage.cmd() == message.cmd(), "execution return message should preserve command");
    }

    {
        const auto script = writeTempFile("c2core_powershell_exec_import.ps1", "function Invoke-C2CoreImported { Write-Output \"import-exec-ok\" }\n");
        Powershell module;

        {
            std::vector<std::string> cmd = {"powershell", "-i", script.string()};
            C2Message message;
            C2Message retMessage;

            ok &= expect(module.init(cmd, message) == 0, "import execution script should be accepted");
            ok &= expect(module.process(message, retMessage) == 0, "import execution script should process");
        }

        {
            std::vector<std::string> cmd = {"powershell", "Invoke-C2CoreImported"};
            C2Message message;
            C2Message retMessage;

            ok &= expect(module.init(cmd, message) == 0, "imported function command should be accepted");
            ok &= expect(module.process(message, retMessage) == 0, "imported function command should process");
            ok &= expectContains(retMessage.returnvalue(), "import-exec-ok", "imported function output should be captured");
        }

        std::filesystem::remove(script);
    }

    {
        const auto script = writeTempFile("c2core_powershell_exec_script.ps1", "Write-Output \"script-exec-ok\"\n");
        Powershell module;
        std::vector<std::string> cmd = {"powershell", "-s", script.string()};
        C2Message message;
        C2Message retMessage;

        ok &= expect(module.init(cmd, message) == 0, "script execution file should be accepted");
        ok &= expect(module.process(message, retMessage) == 0, "script execution file should process");
        ok &= expectContains(retMessage.returnvalue(), "script-exec-ok", "script execution output should be captured");
        ok &= expect(retMessage.cmd() == message.cmd(), "script execution return message should preserve command");

        std::filesystem::remove(script);
    }
#endif

    return ok ? 0 : 1;
}
