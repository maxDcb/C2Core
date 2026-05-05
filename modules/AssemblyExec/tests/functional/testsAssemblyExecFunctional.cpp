#include "../../AssemblyExec.hpp"
#include "../AssemblyExecTestShellcodeGenerator.hpp"
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
#ifdef C2_ASSEMBLYEXEC_DUMMY_EXE
    return C2_ASSEMBLYEXEC_DUMMY_EXE;
#else
    return {};
#endif
}

std::string normalizeMode(const std::string& mode)
{
    if (mode == "thread")
    {
        return "thread";
    }
    if (mode == "process-spoofed" || mode == "processWithSpoofedParent")
    {
        return "processWithSpoofedParent";
    }
    return "process";
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
}

int main(int argc, char** argv)
{
    const std::vector<Input> inputs = {
        {"--payload", "C2_FUNC_ASSEMBLYEXEC_PAYLOAD", "Assembly or shellcode path", false, false, defaultPayloadPath()},
        {"--kind", "C2_FUNC_ASSEMBLYEXEC_KIND", "Payload kind: exe, dll, or raw", false, false, "exe"},
        {"--mode", "C2_FUNC_ASSEMBLYEXEC_MODE", "Execution mode: thread, process, or process-spoofed", false, false, "process"},
        {"--method", "C2_FUNC_ASSEMBLYEXEC_METHOD", "DLL method name for dll mode", false},
        {"--args", "C2_FUNC_ASSEMBLYEXEC_ARGS", "Arguments passed to the assembly entrypoint", false},
        {"--process", "C2_FUNC_ASSEMBLYEXEC_PROCESS", "Optional process to spawn for process mode", false},
        {"--spoofed-parent", "C2_FUNC_ASSEMBLYEXEC_SPOOFED_PARENT", "Optional spoofed parent process path", false},
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsAssemblyExecFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = hasFlag(argc, argv, "--execute");

#ifndef _WIN32
    if (execute)
    {
        std::cout << "testsAssemblyExecFunctional skipped: execution is only supported on Windows in this harness.\n";
        return skipReturnCode;
    }
#endif

    const std::string payload = readInput(inputs[0], argc, argv, interactive);
    const std::string kind = normalizeKind(readInput(inputs[1], argc, argv, interactive));
    const std::string mode = normalizeMode(readInput(inputs[2], argc, argv, interactive));
    const std::string method = readInput(inputs[3], argc, argv, interactive);
    const std::string arguments = readInput(inputs[4], argc, argv, interactive);
    const std::string processToSpawn = readInput(inputs[5], argc, argv, interactive);
    const std::string spoofedParent = readInput(inputs[6], argc, argv, interactive);

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
        return skipMissing("testsAssemblyExecFunctional", missing);
    }

    AssemblyExec module;

    C2Message modeMessage;
    std::vector<std::string> modeCommand = {"assemblyExec", mode};
    if (module.init(modeCommand, modeMessage) != -1)
    {
        std::cerr << "testsAssemblyExecFunctional mode selection failed\n";
        return 1;
    }

    C2Message message;
    std::filesystem::path generatedPath;
    if (kind == "raw")
    {
        std::vector<std::string> command = {"assemblyExec", "--mode", mode, "--raw", payload};
        if (module.init(command, message) != 0)
        {
            std::cerr << "testsAssemblyExecFunctional init failed:\n" << message.returnvalue() << '\n';
            return 1;
        }
    }
    else
    {
        const bool exitProcess = mode != "thread";
        assembly_exec_tests::GeneratedShellcode generated = assembly_exec_tests::generateDonutShellcodeForTest(
            payload,
            kind == "dll" ? method : "",
            arguments,
            currentWindowsArch(),
            exitProcess);
        if (!generated.ok)
        {
#ifndef _WIN32
            std::cout << "testsAssemblyExecFunctional skipped: " << generated.error << '\n';
            return skipReturnCode;
#else
            std::cerr << "testsAssemblyExecFunctional Donut preparation failed:\n" << generated.error << '\n';
            return 1;
#endif
        }

        generatedPath = generated.path;
        ModulePreparedShellcodeTask task;
        task.inputFile = generated.path.string();
        task.payload = generated.bytes;
        task.executionMode = mode;
        task.displayCommand = kind == "dll"
            ? "--mode " + mode + " --donut-dll " + payload + " --method " + method + " -- " + arguments
            : "--mode " + mode + " --donut-exe " + payload + " -- " + arguments;
        if (module.initPreparedShellcode(task, message) != 0)
        {
            std::cerr << "testsAssemblyExecFunctional prepared init failed:\n" << message.returnvalue() << '\n';
            std::filesystem::remove(generatedPath);
            return 1;
        }
    }

    std::cout << "testsAssemblyExecFunctional init OK\n";
    std::cout << "instruction: " << message.instruction() << '\n';
    std::cout << "input: " << message.inputfile() << '\n';

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
    if (!spoofedParent.empty())
    {
        config["spoofedParent"] = spoofedParent;
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
