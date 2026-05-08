#include "../PwSh.hpp"
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
constexpr const char* kLoadModule = "00001";
constexpr const char* kRunDll = "00003";
constexpr const char* kImportModulePS = "00004";
constexpr const char* kScriptPS = "00005";

std::filesystem::path testDataPath(const std::string& name)
{
    return std::filesystem::path(__FILE__).parent_path() / name;
}

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

bool expectContains(const std::string& text, const std::string& needle, const std::string& label)
{
    return expect(text.find(needle) != std::string::npos, label);
}

bool expectLoadMessage(const C2Message& message,
                       const std::filesystem::path& expectedInput,
                       const std::string& expectedType,
                       const std::string& expectedData,
                       const std::string& label)
{
    bool ok = true;
    ok &= expect(message.instruction() == "pwSh", label + ": instruction should be set");
    ok &= expect(message.cmd() == kLoadModule, label + ": load command id should be packed");
    ok &= expect(message.inputfile() == expectedInput.string(), label + ": input file should be packed");
    ok &= expect(message.args() == expectedType, label + ": type should be packed");
    ok &= expect(message.data() == expectedData, label + ": assembly bytes should be packed");
    return ok;
}

bool expectErrorMessage(PwSh& module, int errorCode, const std::string& expected, const std::string& label)
{
    C2Message message;
    message.set_errorCode(errorCode);
    std::string error;

    bool ok = true;
    ok &= expect(module.errorCodeToMsg(message, error) == 0, label + ": errorCodeToMsg should return 0");
    ok &= expect(error == expected, label + ": error text should match");
    return ok;
}
}

int main()
{
    bool ok = true;

    {
        const auto dll = writeTempFileWithExtension("c2core_pwsh_dummy", ".dll", "dll-bytes");
        PwSh module;
        std::vector<std::string> cmd = {"pwSh", "init", dll.string(), "Dummy.Namespace.Type"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "init with custom dll should be accepted");
        ok &= expectLoadMessage(message, dll, "Dummy.Namespace.Type", "dll-bytes", "custom dll init");
        std::filesystem::remove(dll);
    }

    {
        const auto exe = writeTempFileWithExtension("c2core_pwsh_wrong_ext", ".exe", "exe-bytes");
        PwSh module;
        std::vector<std::string> cmd = {"pwSh", "init", exe.string(), "Dummy.Namespace.Type"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "init with unsupported extension should be rejected");
        ok &= expectContains(message.returnvalue(), "Invalid file type", "unsupported extension should explain the file type rule");
        std::filesystem::remove(exe);
    }

    {
        const auto dll = writeTempFileWithExtension("c2core_pwsh_empty_type", ".dll", "dll-bytes");
        PwSh module;
        std::vector<std::string> cmd = {"pwSh", "init", dll.string(), ""};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "init with empty dll type should be rejected");
        ok &= expectContains(message.returnvalue(), "fully-qualified type name", "empty dll type should explain the type rule");
        std::filesystem::remove(dll);
    }

    {
        PwSh module;
        std::vector<std::string> cmd = {"pwSh", "init", "missing.dll", "Missing.Type"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "init with missing dll should be rejected");
        ok &= expectContains(message.returnvalue(), "Couldn't open file", "missing dll should explain the file error");
    }

    {
        PwSh module;
        std::vector<std::string> cmd = {"pwSh", "run", "Write-Output", "hello"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "run command should be accepted");
        ok &= expect(message.instruction() == "pwSh", "run command should set instruction");
        ok &= expect(message.cmd() == kRunDll, "run command should pack run id");
        ok &= expect(message.args() == "Write-Output hello ", "run command should pack arguments with existing spacing behavior");
    }

    {
        PwSh module;
        std::vector<std::string> cmd = {"pwSh", "import", "missing.ps1"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing import script should be rejected");
        ok &= expectContains(message.returnvalue(), "Couldn't open file", "missing import script should explain the file error");
    }

    {
        PwSh module;
        std::vector<std::string> cmd = {"pwSh", "script", "missing.ps1"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing script should be rejected");
        ok &= expectContains(message.returnvalue(), "Couldn't open file", "missing script should explain the file error");
    }

    {
        const auto script = writeTempFile("c2core_pwsh_import.ps1", "function Invoke-C2CorePwShTest { Write-Output \"import-ok\" }\n");
        PwSh module;
        std::vector<std::string> cmd = {"pwSh", "import", script.string()};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "existing import script should be accepted");
        ok &= expect(message.instruction() == "pwSh", "import script should set instruction");
        ok &= expect(message.cmd() == kImportModulePS, "import script should pack import id");
        ok &= expect(message.inputfile() == script.string(), "import script should pack input file");
        ok &= expectContains(message.args(), "New-Module -ScriptBlock", "import script should be wrapped in New-Module");
        ok &= expectContains(message.args(), "Invoke-C2CorePwShTest", "import script should include script content");
        ok &= expectContains(message.args(), "Export-ModuleMember -Function * -Alias *;};", "import script should export module members");
        std::filesystem::remove(script);
    }

    {
        const auto script = writeTempFile("c2core_pwsh_script.ps1", "Write-Output \"script-ok\"\n");
        PwSh module;
        std::vector<std::string> cmd = {"pwSh", "script", script.string()};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "existing script should be accepted");
        ok &= expect(message.instruction() == "pwSh", "script should set instruction");
        ok &= expect(message.cmd() == kScriptPS, "script should pack script id");
        ok &= expect(message.inputfile() == script.string(), "script should pack input file");
        ok &= expectContains(message.args(), "Invoke-Command -ScriptBlock", "script should be wrapped in Invoke-Command");
        ok &= expectContains(message.args(), "script-ok", "script should include script content");
        std::filesystem::remove(script);
    }

    {
        PwSh module;
        std::vector<std::string> cmd = {"pwSh", "unknown"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "unknown command should be rejected");
    }

    {
        PwSh module;

        ok &= expectErrorMessage(module, 1, "Failed: CLRCreateInstance", "error code 1");
        ok &= expectErrorMessage(module, 2, "Failed: GetRuntime", "error code 2");
        ok &= expectErrorMessage(module, 3, "Failed: RuntimeInfo - IsLoadable", "error code 3");
        ok &= expectErrorMessage(module, 4, "Failed: RuntimeInfo - GetInterface CLRRuntimeHost", "error code 4");
        ok &= expectErrorMessage(module, 5, "Failed: ClrRuntimeHost - Start", "error code 5");
        ok &= expectErrorMessage(module, 6, "Failed: RuntimeInfo - GetInterface CorRuntimeHost", "error code 6");
        ok &= expectErrorMessage(module, 7, "Failed: CorHost - GetDefaultDomain", "error code 7");
        ok &= expectErrorMessage(module, 8, "Failed: AppDomainThunk - QueryInterface", "error code 8");
        ok &= expectErrorMessage(module, 11, "Failed: IdentityManagerProc", "error code 11");
        ok &= expectErrorMessage(module, 12, "Failed: IdentityMnaager - GetBindingIdentityFromStream", "error code 12");
        ok &= expectErrorMessage(module, 13, "Failed: PwSh runner assembly could not be loaded in the current CLR AppDomain. This usually means the beacon process already has an incompatible CLR/AppDomain context; retry from a fresh beacon process or a process without an existing conflicting CLR. Original stage: DefaultAppDomain - Load_2", "error code 13");
        ok &= expectErrorMessage(module, 14, "Failed: DefaultAppDomain - Load_3", "error code 14");
        ok &= expectErrorMessage(module, 15, "Failed: No module loaded", "error code 15");
        ok &= expectErrorMessage(module, 21, "Failed: Assembly - GetType_2", "error code 21");
        ok &= expectErrorMessage(module, 22, "Failed: Type - InvokeMember_3", "error code 22");
        ok &= expectErrorMessage(module, 23, "Failed: InvokeMember_3 - COM exception", "error code 23");
        ok &= expectErrorMessage(module, 24, "Failed: InvokeMember_3 - unknown exception", "error code 24");
        ok &= expectErrorMessage(module, 31, "Failed: Assembly null", "error code 31");
        ok &= expectErrorMessage(module, 32, "Failed: Assembly - EntryPoint", "error code 32");
        ok &= expectErrorMessage(module, 33, "Failed: Invoke_3", "error code 33");
        ok &= expectErrorMessage(module, 34, "Failed: Invoke_3 - COM exception", "error code 34");
        ok &= expectErrorMessage(module, 35, "Failed: Invoke_3 - unknown exception", "error code 35");
        ok &= expectErrorMessage(module, 999, "Failed: Unknown error", "unknown error code");

        C2Message noError;
        noError.set_errorCode(0);
        std::string untouched = "unchanged";
        ok &= expect(module.errorCodeToMsg(noError, untouched) == 0, "zero error code should return 0");
        ok &= expect(untouched == "unchanged", "zero error code should leave existing error text unchanged");
    }

#ifdef _WIN32
    {
        const auto runnerDll = testDataPath("rdm.dll");
        ok &= expect(std::filesystem::exists(runnerDll), "rdm.dll test runner should exist");

        if (std::filesystem::exists(runnerDll))
        {
            PwSh module;

            {
                std::vector<std::string> cmd = {"pwSh", "init", runnerDll.string(), "rdm.rdm"};
                C2Message message;
                C2Message retMessage;

                ok &= expect(module.init(cmd, message) == 0, "runner dll init should be accepted");
                ok &= expect(module.process(message, retMessage) == 0, "runner dll should load");
                ok &= expect(retMessage.errorCode() == -1, "runner dll load should not set an error code");
                ok &= expect(retMessage.returnvalue() == "Success", "runner dll load should report success");
            }

            {
                std::vector<std::string> cmd = {"pwSh", "run", "Write-Output", "\"c2core-pwsh-exec\""};
                C2Message message;
                C2Message retMessage;

                ok &= expect(module.init(cmd, message) == 0, "runner command should be accepted");
                ok &= expect(module.process(message, retMessage) == 0, "runner command should execute");
                ok &= expect(retMessage.errorCode() == -1, "runner command should not set an error code");
                ok &= expectContains(retMessage.returnvalue(), "c2core-pwsh-exec", "runner command output should be captured");
            }

            const auto script = writeTempFile("c2core_pwsh_exec_import.ps1", "function Invoke-C2CorePwShImported { Write-Output \"import-exec-ok\" }\n");
            {
                std::vector<std::string> cmd = {"pwSh", "import", script.string()};
                C2Message message;
                C2Message retMessage;

                ok &= expect(module.init(cmd, message) == 0, "runner import script should be accepted");
                ok &= expect(module.process(message, retMessage) == 0, "runner import script should execute");
                ok &= expect(retMessage.errorCode() == -1, "runner import script should not set an error code");
            }

            {
                std::vector<std::string> cmd = {"pwSh", "run", "Invoke-C2CorePwShImported"};
                C2Message message;
                C2Message retMessage;

                ok &= expect(module.init(cmd, message) == 0, "runner imported function command should be accepted");
                ok &= expect(module.process(message, retMessage) == 0, "runner imported function command should execute");
                ok &= expectContains(retMessage.returnvalue(), "import-exec-ok", "runner imported function output should be captured");
            }
            std::filesystem::remove(script);

            const auto runScript = writeTempFile("c2core_pwsh_exec_script.ps1", "Write-Output \"script-exec-ok\"\n");
            {
                std::vector<std::string> cmd = {"pwSh", "script", runScript.string()};
                C2Message message;
                C2Message retMessage;

                ok &= expect(module.init(cmd, message) == 0, "runner script should be accepted");
                ok &= expect(module.process(message, retMessage) == 0, "runner script should execute");
                ok &= expectContains(retMessage.returnvalue(), "script-exec-ok", "runner script output should be captured");
            }
            std::filesystem::remove(runScript);
        }
    }
#endif

    return ok ? 0 : 1;
}
