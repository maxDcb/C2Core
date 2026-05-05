#include "../Inject.hpp"
#include "../../AssemblyExec/tests/AssemblyExecTestShellcodeGenerator.hpp"
#include "../../tests/TestHelpers.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

using namespace test_helpers;

namespace
{
std::string dummyExePath()
{
#ifdef C2_INJECT_DUMMY_EXE
    return C2_INJECT_DUMMY_EXE;
#else
    return {};
#endif
}

bool expectInjectMessage(const C2Message& message,
                         const std::filesystem::path& expectedInput,
                         int expectedPid,
                         const std::string& expectedCmdPart,
                         const std::string& label)
{
    bool ok = true;
    ok &= expect(message.instruction() == "inject", label + ": instruction should be set");
    ok &= expect(message.inputfile() == expectedInput.string(), label + ": input file should be packed");
    ok &= expect(message.pid() == expectedPid, label + ": pid should be packed");
    ok &= expect(message.cmd().find(expectedCmdPart) != std::string::npos, label + ": original command tail should be packed");
    ok &= expect(!message.data().empty(), label + ": payload should be non-empty");
    return ok;
}

#ifdef _WIN32
bool expectPreparedDonutMessage(const std::filesystem::path& sourcePath,
                                int expectedPid,
                                const std::string& arguments,
                                const std::string& arch,
                                const std::string& displayCommand,
                                const std::string& label)
{
    bool ok = true;
    assembly_exec_tests::GeneratedShellcode generated = assembly_exec_tests::generateDonutShellcodeForTest(
        sourcePath.string(),
        "",
        arguments,
        arch,
        true);
    ok &= expect(generated.ok, label + ": Donut test shellcode should be generated: " + generated.error);
    if (!ok)
        return false;

    Inject module;
    ModulePreparedShellcodeTask task;
    task.inputFile = generated.path.string();
    task.payload = generated.bytes;
    task.pid = expectedPid;
    task.displayCommand = displayCommand;

    C2Message message;
    ok &= expect(module.initPreparedShellcode(task, message) == 0, label + ": prepared shellcode should be packed");
    ok &= expectInjectMessage(message, generated.path, expectedPid, displayCommand, label);
    ok &= expect(message.data() == generated.bytes, label + ": generated shellcode bytes should be packed");
    std::filesystem::remove(generated.path);
    return ok;
}
#endif

#ifdef _WIN32
class ChildProcess
{
public:
    explicit ChildProcess(const std::string& exePath)
    {
        STARTUPINFOA startupInfo{};
        startupInfo.cb = sizeof(startupInfo);

        std::string commandLine = "\"" + exePath + "\" --sleep";
        std::vector<char> commandLineBuffer(commandLine.begin(), commandLine.end());
        commandLineBuffer.push_back('\0');

        PROCESS_INFORMATION processInfo{};
        if (CreateProcessA(exePath.c_str(),
                           commandLineBuffer.data(),
                           nullptr,
                           nullptr,
                           FALSE,
                           CREATE_NO_WINDOW,
                           nullptr,
                           nullptr,
                           &startupInfo,
                           &processInfo))
        {
            m_process = processInfo.hProcess;
            m_thread = processInfo.hThread;
            m_pid = static_cast<int>(processInfo.dwProcessId);
        }
    }

    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;

    ~ChildProcess()
    {
        terminate();
        if (m_thread != nullptr)
        {
            CloseHandle(m_thread);
        }
        if (m_process != nullptr)
        {
            CloseHandle(m_process);
        }
    }

    bool started() const
    {
        return m_process != nullptr && m_pid > 0;
    }

    int pid() const
    {
        return m_pid;
    }

    void terminate()
    {
        if (m_process != nullptr && WaitForSingleObject(m_process, 0) == WAIT_TIMEOUT)
        {
            TerminateProcess(m_process, 0);
            WaitForSingleObject(m_process, 3000);
        }
    }

private:
    HANDLE m_process = nullptr;
    HANDLE m_thread = nullptr;
    int m_pid = -1;
};

std::string endlessLoopPayload()
{
#if defined(_M_ARM64) || defined(__aarch64__)
    const char payload[] = {
        static_cast<char>(0x00),
        static_cast<char>(0x00),
        static_cast<char>(0x00),
        static_cast<char>(0x14)
    };
#else
    const char payload[] = {static_cast<char>(0xEB), static_cast<char>(0xFE)};
#endif
    return std::string(payload, sizeof(payload));
}
#endif
}

int main()
{
    bool ok = true;
    const std::string dummyExe = dummyExePath();
    const std::string currentArch = buildWindowsArch();

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
        Inject module;
        std::vector<std::string> cmd = {"inject"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing parameters should be rejected");
    }

    {
        Inject module;
        std::vector<std::string> cmd = {"inject", "-x", "payload.bin", "1234"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "unknown payload option should be rejected");
        ok &= expect(message.returnvalue().find("Unknown inject option") != std::string::npos, "unknown payload option should explain the failure");
    }

    {
        Inject module;
        std::vector<std::string> cmd = {"inject", "-d", "payload.dll", "1234"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "DLL mode without method should be rejected");
        ok &= expect(message.returnvalue().find("Method is mandatory") != std::string::npos, "DLL mode should explain missing method");
    }

    {
        Inject module;
        std::vector<std::string> cmd = {"inject", "--donut-exe", "payload.exe", "--pid", "1234", "--", "alpha", "beta"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "Donut EXE mode should be delegated to TeamServer");
        ok &= expect(message.returnvalue().find("TeamServer shellcode service") != std::string::npos, "Donut delegation should explain TeamServer ownership");
    }

    {
        Inject module;
        std::vector<std::string> cmd = {"inject", "--donut-dll", "payload.dll", "--pid", "1234", "--method", "Run"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "Donut DLL mode should be delegated to TeamServer");
        ok &= expect(message.returnvalue().find("TeamServer shellcode service") != std::string::npos, "Donut DLL delegation should explain TeamServer ownership");
    }

    {
        const auto raw = writeTempFile("c2core_inject_empty_raw.bin", "");
        Inject module;
        std::vector<std::string> cmd = {"inject", "-r", raw.string(), "1234"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "empty raw shellcode file should be rejected");
        ok &= expect(message.returnvalue().find("Payload empty") != std::string::npos, "empty payload error should explain the failure");
        std::filesystem::remove(raw);
    }

    {
        const auto raw = writeTempFile("c2core_inject_raw.bin", "raw-bytes");
        Inject module;
        std::vector<std::string> cmd = {"inject", "-r", raw.string(), "-1"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "existing raw shellcode file should be accepted");
        ok &= expectInjectMessage(message, raw, -1, "-r", "raw shellcode with spawn pid");
        ok &= expect(message.data() == "raw-bytes", "raw bytes should be packed");
        std::filesystem::remove(raw);
    }

    {
        const auto raw = writeTempFile("c2core_inject_raw_positive_pid.bin", "pid-bytes");
        Inject module;
        std::vector<std::string> cmd = {"inject", "-r", raw.string(), "4321"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "raw shellcode with positive pid should be accepted");
        ok &= expectInjectMessage(message, raw, 4321, "4321", "raw shellcode with explicit pid");
        ok &= expect(message.data() == "pid-bytes", "positive pid raw bytes should be packed");
        std::filesystem::remove(raw);
    }

#ifdef _WIN32
    if (dummyExe.empty())
    {
        ok &= expect(false, "dummy exe path should be provided by CMake");
    }
    else
    {
        const std::filesystem::path dummyPath(dummyExe);
        ok &= expect(std::filesystem::exists(dummyPath), "dummy exe should exist before Donut and process tests");

        {
            Inject module;
            module.setWindowsArch(currentArch);
            std::vector<std::string> cmd = {"inject", "--donut-exe", dummyPath.string(), "--pid", "1234", "--", "alpha", "beta gamma"};
            C2Message message;

            ok &= expect(module.init(cmd, message) == -1, "dummy exe Donut mode should be prepared by TeamServer");
            ok &= expect(message.returnvalue().find("TeamServer shellcode service") != std::string::npos, "dummy exe Donut mode should explain TeamServer preparation");
            ok &= expectPreparedDonutMessage(
                dummyPath,
                1234,
                "alpha beta gamma",
                currentArch,
                "--donut-exe " + dummyPath.string() + " --pid 1234 -- alpha beta gamma",
                "dummy exe TeamServer-prepared Donut inject");
        }

        {
            ok &= expectPreparedDonutMessage(
                dummyPath,
                -1,
                "--spawn",
                currentArch,
                "--donut-exe " + dummyPath.string() + " --pid -1 -- --spawn",
                "dummy exe TeamServer-prepared Donut spawn inject");
        }

        {
            Inject module;
            C2Message message;
            message.set_pid(2147483647);
            message.set_data(endlessLoopPayload());
            C2Message retMessage;

            ok &= expect(module.process(message, retMessage) == 0, "process should return normally for an invalid pid");
            ok &= expect(retMessage.errorCode() > 0, "invalid pid should set an error code");
            ok &= expect(retMessage.returnvalue() == "OpenProcess failed.", "invalid pid should report OpenProcess failure");
            std::string errorMsg;
            ok &= expect(module.errorCodeToMsg(retMessage, errorMsg) == 0, "invalid pid should map error text");
            ok &= expect(errorMsg == retMessage.returnvalue(), "invalid pid error text should come from returnvalue");
        }

        {
            Inject module;
            nlohmann::json config;
            config["process"] = "Z:\\c2core_missing_inject_target.exe";
            config["syscall"] = true;
            ok &= expect(module.initConfig(config) == 0, "initConfig should accept process and syscall settings");

            C2Message message;
            message.set_pid(-1);
            message.set_data(endlessLoopPayload());
            C2Message retMessage;

            ok &= expect(module.process(message, retMessage) == 0, "spawn injection failure path should return normally");
            ok &= expect(retMessage.errorCode() > 0, "invalid spawn target should set an error code");
            ok &= expect(retMessage.returnvalue() == "CreateProcess failed.", "invalid spawn target should report CreateProcess failure");
            std::string errorMsg;
            ok &= expect(module.errorCodeToMsg(retMessage, errorMsg) == 0, "invalid spawn target should map error text");
            ok &= expect(errorMsg == retMessage.returnvalue(), "invalid spawn target error text should come from returnvalue");
        }

        {
            ChildProcess target(dummyPath.string());
            ok &= expect(target.started(), "dummy target process should start");

            if (target.started())
            {
                Inject module;
                C2Message message;
                message.set_pid(target.pid());
                message.set_data(endlessLoopPayload());
                C2Message retMessage;

                ok &= expect(module.process(message, retMessage) == 0, "process should return normally for a live dummy pid");
                ok &= expect(retMessage.returnvalue() == "Process injected.", "live dummy pid should report injection success");
            }
        }
    }
#endif

    return ok ? 0 : 1;
}
