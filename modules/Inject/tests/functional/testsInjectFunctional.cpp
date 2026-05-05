#include "../../Inject.hpp"
#include "../../../AssemblyExec/tests/AssemblyExecTestShellcodeGenerator.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

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
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsInjectFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = hasFlag(argc, argv, "--execute");

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
    const std::string arguments = readInput(inputs[4], argc, argv, interactive);
    const std::string processToSpawn = readInput(inputs[5], argc, argv, interactive);
    const std::string useSyscall = readInput(inputs[6], argc, argv, interactive);

    std::vector<Input> missing;
    if (payload.empty())
    {
        missing.push_back(inputs[0]);
    }
    if (kind == "dll" && method.empty())
    {
        missing.push_back(inputs[3]);
    }
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

    C2Message result;
    module.process(message, result);
    std::cout << result.returnvalue() << '\n';
    if (!generatedPath.empty())
    {
        std::filesystem::remove(generatedPath);
    }
    return 0;
}
