#include "../AssemblyExec.hpp"
#include "AssemblyExecTestShellcodeGenerator.hpp"
#include "../../tests/TestHelpers.hpp"

#include <filesystem>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include "../../ModuleCmd/Tools.hpp"
#endif

using namespace test_helpers;

namespace
{
std::string dummyExePath()
{
#ifdef C2_ASSEMBLYEXEC_DUMMY_EXE
    return C2_ASSEMBLYEXEC_DUMMY_EXE;
#else
    return {};
#endif
}

bool expectAssemblyMessage(const C2Message& message,
                           const std::filesystem::path& expectedInput,
                           const std::string& expectedMode,
                           const std::string& expectedCmdPart,
                           const std::string& label)
{
    bool ok = true;
    ok &= expect(message.instruction() == "assemblyExec", label + ": instruction should be set");
    ok &= expect(message.inputfile() == expectedInput.string(), label + ": input file should be packed");
    ok &= expect(message.args() == expectedMode, label + ": execution mode should be packed");
    ok &= expect(message.pid() == -1, label + ": pid should default to -1");
    ok &= expect(message.cmd().find(expectedCmdPart) != std::string::npos, label + ": original command tail should be packed");
    ok &= expect(!message.data().empty(), label + ": payload should be non-empty");
    return ok;
}

bool expectPreparedDonutMessage(const std::filesystem::path& sourcePath,
                                const std::string& mode,
                                const std::string& method,
                                const std::string& arguments,
                                const std::string& arch,
                                const std::string& expectedMode,
                                const std::string& displayCommand,
                                const std::string& label)
{
    bool ok = true;
    const bool exitProcess = mode != "thread";
    assembly_exec_tests::GeneratedShellcode generated = assembly_exec_tests::generateDonutShellcodeForTest(
        sourcePath.string(),
        method,
        arguments,
        arch,
        exitProcess);
    ok &= expect(generated.ok, label + ": Donut test shellcode should be generated: " + generated.error);
    if (!ok)
        return false;

    AssemblyExec module;
    ModulePreparedShellcodeTask task;
    task.inputFile = generated.path.string();
    task.payload = generated.bytes;
    task.executionMode = mode;
    task.displayCommand = displayCommand;

    C2Message message;
    ok &= expect(module.initPreparedShellcode(task, message) == 0, label + ": prepared shellcode should be packed");
    ok &= expectAssemblyMessage(message, generated.path, expectedMode, displayCommand, label);
    ok &= expect(message.data() == generated.bytes, label + ": generated shellcode bytes should be packed");
    std::filesystem::remove(generated.path);
    return ok;
}
}

int main()
{
    bool ok = true;
    const std::string dummyExe = dummyExePath();
    const std::string currentArch = buildWindowsArch();

#ifdef _WIN32
    {
        StdCapture capture;
        capture.BeginCapture();
        const char* crtOutput = "crt-output\n";
        std::fwrite(crtOutput, 1, std::strlen(crtOutput), stdout);
        const char* winOutput = "win32-output\n";
        DWORD written = 0;
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), winOutput, static_cast<DWORD>(std::strlen(winOutput)), &written, nullptr);
        capture.EndCapture();
        const std::string captured = capture.GetCapture();
        ok &= expect(captured.find("crt-output") != std::string::npos, "StdCapture should capture CRT stdout");
        ok &= expect(captured.find("win32-output") != std::string::npos, "StdCapture should capture Win32 stdout handle");
    }
#endif

    {
        AssemblyExec module;
        std::vector<std::string> cmd = {"assemblyExec", "thread"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "thread mode should be handled locally");
        ok &= expect(message.returnvalue() == "thread mode.\n", "thread mode should report selected mode");
    }

    {
        AssemblyExec module;
        std::vector<std::string> cmd = {"assemblyExec", "process"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "process mode should be handled locally");
        ok &= expect(message.returnvalue() == "process mode.\n", "process mode should report selected mode");
    }

    {
        AssemblyExec module;
        std::vector<std::string> cmd = {"assemblyExec", "processWithSpoofedParent"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "spoofed-parent mode should be handled locally");
        ok &= expect(message.returnvalue() == "process mode with parent spoofing.\n", "spoofed-parent mode should report selected mode");
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
        std::vector<std::string> cmd = {"assemblyExec", "--mode", "process", "--raw", raw.string()};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "existing raw shellcode file should be accepted");
        ok &= expectAssemblyMessage(message, raw, "1", "--raw", "raw process mode");
        ok &= expect(message.data() == "raw-bytes", "raw bytes should be packed");
        std::filesystem::remove(raw);
    }

    {
        const auto raw = writeTempFile("c2core_assembly_raw_thread.bin", "thread-bytes");
        AssemblyExec module;
        C2Message modeMessage;
        std::vector<std::string> modeCmd = {"assemblyExec", "thread"};
        ok &= expect(module.init(modeCmd, modeMessage) == -1, "thread mode selection should be accepted before payload init");

        std::vector<std::string> cmd = {"assemblyExec", "-r", raw.string()};
        C2Message message;
        ok &= expect(module.init(cmd, message) == 0, "raw shellcode should honor thread mode");
        ok &= expectAssemblyMessage(message, raw, "0", "-r", "raw thread mode");
        ok &= expect(message.data() == "thread-bytes", "thread raw bytes should be packed");
        std::filesystem::remove(raw);
    }

    {
        const auto raw = writeTempFile("c2core_assembly_raw_spoof.bin", "spoof-bytes");
        AssemblyExec module;
        C2Message modeMessage;
        std::vector<std::string> modeCmd = {"assemblyExec", "processWithSpoofedParent"};
        ok &= expect(module.init(modeCmd, modeMessage) == -1, "spoofed-parent mode selection should be accepted before payload init");

        std::vector<std::string> cmd = {"assemblyExec", "-r", raw.string()};
        C2Message message;
        ok &= expect(module.init(cmd, message) == 0, "raw shellcode should honor spoofed-parent mode");
        ok &= expectAssemblyMessage(message, raw, "2", "-r", "raw spoofed-parent mode");
        ok &= expect(message.data() == "spoof-bytes", "spoof raw bytes should be packed");
        std::filesystem::remove(raw);
    }

    {
        AssemblyExec module;
        std::vector<std::string> cmd = {"assemblyExec", "-x", "payload.bin"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "unknown payload option should be rejected");
        ok &= expect(message.returnvalue().find("Unknown assemblyExec option") != std::string::npos, "unknown payload option should explain accepted tags");
    }

    {
        AssemblyExec module;
        std::vector<std::string> cmd = {"assemblyExec", "-d", "payload.dll"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "DLL mode without method should be rejected");
        ok &= expect(message.returnvalue().find("Method is mandatory") != std::string::npos, "DLL mode should explain missing method");
    }

    {
        AssemblyExec module;
        std::vector<std::string> cmd = {"assemblyExec", "--donut-exe", "payload.exe"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "Donut mode should be rejected by module init");
        ok &= expect(message.returnvalue().find("TeamServer shellcode service") != std::string::npos, "Donut mode should point to TeamServer shellcode service");
    }

    if (dummyExe.empty())
    {
#ifdef _WIN32
        ok &= expect(false, "dummy exe path should be provided by CMake");
#endif
    }
    else
    {
        const std::filesystem::path dummyPath(dummyExe);
        ok &= expect(std::filesystem::exists(dummyPath), "dummy exe should exist before Donut tests");

        {
            AssemblyExec module;
            module.setWindowsArch(currentArch);
            std::vector<std::string> cmd = {"assemblyExec", "-e", dummyPath.string()};
            C2Message message;

            ok &= expect(module.init(cmd, message) == -1, "dummy exe Donut mode should be prepared by TeamServer");
            ok &= expect(message.returnvalue().find("TeamServer shellcode service") != std::string::npos, "dummy exe Donut mode should explain TeamServer preparation");
            ok &= expectPreparedDonutMessage(
                dummyPath,
                "process",
                "",
                "",
                currentArch,
                "1",
                "--mode process --donut-exe " + dummyPath.string(),
                "dummy exe TeamServer-prepared Donut process mode");
        }

        {
            ok &= expectPreparedDonutMessage(
                dummyPath,
                "thread",
                "",
                "alpha beta gamma",
                currentArch,
                "0",
                "--mode thread --donut-exe " + dummyPath.string() + " -- alpha beta gamma",
                "dummy exe TeamServer-prepared Donut thread mode with args");
        }

        {
            ok &= expectPreparedDonutMessage(
                dummyPath,
                "processWithSpoofedParent",
                "",
                "--flag",
                currentArch,
                "2",
                "--mode processWithSpoofedParent --donut-exe " + dummyPath.string() + " -- --flag",
                "dummy exe TeamServer-prepared Donut spoofed-parent mode");
        }

        {
            AssemblyExec module;
            nlohmann::json config;
            config["process"] = "Z:\\c2core_missing_assemblyexec_target.exe";
            ok &= expect(module.initConfig(config) == 0, "initConfig should accept a custom process path");

            C2Message message;
            message.set_args("1");
            message.set_data("raw-bytes");
            C2Message retMessage;

            ok &= expect(module.process(message, retMessage) == 0, "missing process target should return through C2Message");
            ok &= expect(retMessage.errorCode() > 0, "missing process target should set an error code");
            ok &= expect(retMessage.returnvalue().find("Error: Process failed to start") != std::string::npos, "missing process target should explain the failure");
            std::string errorMsg;
            ok &= expect(module.errorCodeToMsg(retMessage, errorMsg) == 0, "missing process target should map error text");
            ok &= expect(errorMsg == retMessage.returnvalue(), "missing process target error text should come from returnvalue");
        }
    }

    return ok ? 0 : 1;
}
