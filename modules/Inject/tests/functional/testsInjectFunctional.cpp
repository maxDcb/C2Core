#include "../../Inject.hpp"
#include "../../../AssemblyExec/tests/AssemblyExecTestShellcodeGenerator.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace functional_tests;

namespace
{
std::string defaultPayloadPath()
{
#ifdef C2_INJECT_DUMMY_EXE
    return C2_INJECT_DUMMY_EXE;
#else
    return {};
#endif
}

std::string defaultSpawnProcess()
{
#ifdef C2_INJECT_DUMMY_EXE
    return C2_INJECT_DUMMY_EXE;
#else
    return {};
#endif
}

std::string normalizeKind(const std::string& kind)
{
    if (kind == "dll")
    {
        return "dll";
    }
    if (kind == "raw")
    {
        return "raw";
    }
    return "exe";
}

bool isTruthy(const std::string& value)
{
    return value == "1" || value == "true" || value == "TRUE" || value == "yes" || value == "YES";
}

std::string currentWindowsArch()
{
#if defined(_M_ARM64) || defined(__aarch64__)
    return "arm64";
#elif defined(_M_IX86) || defined(__i386__)
    return "x86";
#else
    return "x64";
#endif
}

bool parsePid(const std::string& value, int& pid)
{
    try
    {
        size_t parsed = 0;
        pid = std::stoi(value, &parsed);
        return parsed == value.size();
    }
    catch (...)
    {
        return false;
    }
}
}

int main(int argc, char** argv)
{
    const std::vector<Input> inputs = {
        {"--payload", "C2_FUNC_INJECT_PAYLOAD", "Payload path", false, false, defaultPayloadPath()},
        {"--kind", "C2_FUNC_INJECT_KIND", "Payload kind: exe, dll, or raw", false, false, "exe"},
        {"--pid", "C2_FUNC_INJECT_PID", "Target pid, or -1 to spawn a new process", false, false, "-1"},
        {"--method", "C2_FUNC_INJECT_METHOD", "DLL method name for dll mode", false},
        {"--args", "C2_FUNC_INJECT_ARGS", "Arguments passed to the payload", false},
        {"--spawn-process", "C2_FUNC_INJECT_PROCESS", "Process path to spawn when pid is negative", false, false, defaultSpawnProcess()},
        {"--syscall", "C2_FUNC_INJECT_SYSCALL", "Enable syscall path (1/0)", false, false, "0"},
        {"--verify-file", "C2_FUNC_INJECT_VERIFY_FILE", "File written by the injected payload", false},
        {"--expect", "C2_FUNC_INJECT_EXPECT", "Expected content in the new file", false},
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsInjectFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = shouldExecute(argc, argv, "C2_FUNC_INJECT_EXECUTE");

#ifndef _WIN32
    if (execute)
    {
        std::cout << "testsInjectFunctional skipped: execution is only supported on Windows in this harness.\n";
        return skipReturnCode;
    }
#endif

    const std::string payload = readInput(inputs[0], argc, argv, interactive);
    const std::string kind = normalizeKind(readInput(inputs[1], argc, argv, interactive));
    const std::string pid = readInput(inputs[2], argc, argv, interactive);
    const std::string method = readInput(inputs[3], argc, argv, interactive);
    std::string arguments = readInput(inputs[4], argc, argv, interactive);
    const std::string processToSpawn = readInput(inputs[5], argc, argv, interactive);
    const std::string useSyscall = readInput(inputs[6], argc, argv, interactive);
    std::string verifyFile = readInput(inputs[7], argc, argv, interactive);
    std::string expected = readInput(inputs[8], argc, argv, interactive);
    bool removeMarker = false;
    if (execute && kind == "exe" && payload == defaultPayloadPath())
    {
        if (verifyFile.empty())
        {
            verifyFile = (std::filesystem::temp_directory_path() /
                ("c2core-inject-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".txt")).string();
            removeMarker = true;
        }
        if (arguments.empty())
            arguments = "--marker \"" + verifyFile + "\"";
        if (expected.empty())
            expected = "inject-dummy";
    }

    std::vector<Input> missing;
    if (payload.empty())
    {
        missing.push_back(inputs[0]);
    }
    if (kind == "dll" && method.empty())
    {
        missing.push_back(inputs[3]);
    }
    if (execute && verifyFile.empty())
        missing.push_back(inputs[7]);
    if (execute && expected.empty())
        missing.push_back(inputs[8]);
    if (!missing.empty())
    {
        return skipMissing("testsInjectFunctional", missing);
    }

    Inject module;
    C2Message message;
    std::filesystem::path generatedPath;
    if (kind == "raw")
    {
        std::vector<std::string> command = {"inject", "-r", payload, pid};
        if (module.init(command, message) != 0)
        {
            std::cerr << "testsInjectFunctional init failed:\n" << message.returnvalue() << '\n';
            return 1;
        }
    }
    else
    {
        int parsedPid = -1;
        if (!parsePid(pid, parsedPid))
        {
            std::cerr << "testsInjectFunctional invalid pid: " << pid << '\n';
            return 1;
        }

        assembly_exec_tests::GeneratedShellcode generated = assembly_exec_tests::generateDonutShellcodeForTest(
            payload,
            kind == "dll" ? method : "",
            arguments,
            currentWindowsArch(),
            true);
        if (!generated.ok)
        {
#ifndef _WIN32
            std::cout << "testsInjectFunctional skipped: " << generated.error << '\n';
            return skipReturnCode;
#else
            std::cerr << "testsInjectFunctional Donut preparation failed:\n" << generated.error << '\n';
            return 1;
#endif
        }

        generatedPath = generated.path;
        ModulePreparedShellcodeTask task;
        task.inputFile = generated.path.string();
        task.payload = generated.bytes;
        task.pid = parsedPid;
        task.displayCommand = kind == "dll"
            ? "--donut-dll " + payload + " --pid " + pid + " --method " + method + " -- " + arguments
            : "--donut-exe " + payload + " --pid " + pid + " -- " + arguments;
        if (module.initPreparedShellcode(task, message) != 0)
        {
            std::cerr << "testsInjectFunctional prepared init failed:\n" << message.returnvalue() << '\n';
            std::filesystem::remove(generatedPath);
            return 1;
        }
    }

    std::cout << "testsInjectFunctional init OK\n";
    std::cout << "instruction: " << message.instruction() << '\n';
    std::cout << "pid: " << message.pid() << '\n';

    if (!execute)
    {
        std::cout << "execution skipped; pass --execute to run the module process path.\n";
        if (!generatedPath.empty())
        {
            std::filesystem::remove(generatedPath);
        }
        return 0;
    }

    nlohmann::json config;
    if (!processToSpawn.empty())
    {
        config["process"] = processToSpawn;
    }
    if (isTruthy(useSyscall))
    {
        config["syscall"] = true;
    }
    if (!config.empty())
    {
        module.initConfig(config);
    }

#ifdef _WIN32
    PROCESS_INFORMATION owned{};
    if (pid == "-1" && kind == "exe" && payload == defaultPayloadPath() &&
        processToSpawn == defaultSpawnProcess())
    {
        STARTUPINFOA startup{};
        startup.cb = sizeof(startup);
        std::string targetCommand = "\"" + defaultSpawnProcess() + "\" --sleep";
        if (!CreateProcessA(nullptr, targetCommand.data(), nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &startup, &owned))
        {
            std::cerr << "Could not create the test-owned injection target.\n";
            if (!generatedPath.empty()) std::filesystem::remove(generatedPath);
            return 1;
        }
        CloseHandle(owned.hThread);
        message.set_pid(static_cast<int>(owned.dwProcessId));
    }
#endif

    const FileSnapshot before = snapshotFile(verifyFile);
    C2Message request = test_helpers::roundTripMessage(message);
    C2Message result;
    module.process(request, result);
    const C2Message response = test_helpers::roundTripMessage(result);
    Inject receiver;
    std::string error;
    receiver.errorCodeToMsg(response, error);
    const bool passed = response.instruction() == "inject" &&
        response.errorCode() == 0 && error.empty() &&
        response.returnvalue().find("Process injected") != std::string::npos &&
        waitForFileContent(verifyFile, expected, before);
    if (!passed)
        std::cerr << "Injected payload did not create a fresh marker: " << error << '\n';
    else
        std::cout << response.returnvalue() << '\n';
    if (removeMarker)
        std::filesystem::remove(verifyFile);
#ifdef _WIN32
    if (owned.hProcess != nullptr)
    {
        TerminateProcess(owned.hProcess, 0);
        CloseHandle(owned.hProcess);
    }
#endif
    if (!generatedPath.empty())
    {
        std::filesystem::remove(generatedPath);
    }
    return passed ? 0 : 1;
}
