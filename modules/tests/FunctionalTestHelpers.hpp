#pragma once

#include "local/MessageTestHelpers.hpp"

#include <cstdlib>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

namespace functional_tests
{
constexpr int skipReturnCode = 77;

struct Input
{
    const char* option;
    const char* env;
    const char* description;
    bool required;
    bool secret = false;
    std::string defaultValue;
};

inline bool hasFlag(int argc, char** argv, const std::string& flag)
{
    for (int i = 1; i < argc; ++i)
    {
        if (argv[i] == flag)
        {
            return true;
        }
    }
    return false;
}

inline std::string optionValue(int argc, char** argv, const std::string& option)
{
    for (int i = 1; i + 1 < argc; ++i)
    {
        if (argv[i] == option)
        {
            return argv[i + 1];
        }
    }
    return {};
}

inline std::string envValue(const char* name)
{
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

inline bool shouldExecute(int argc, char** argv, const char* env)
{
    return hasFlag(argc, argv, "--execute") || envValue(env) == "1";
}

struct FileSnapshot
{
    bool exists = false;
    std::filesystem::file_time_type modified{};
};

inline FileSnapshot snapshotFile(const std::string& path)
{
    std::error_code error;
    FileSnapshot snapshot;
    snapshot.exists = std::filesystem::exists(path, error);
    if (snapshot.exists && !error)
        snapshot.modified = std::filesystem::last_write_time(path, error);
    return snapshot;
}

inline bool waitForFileContent(const std::string& path, const std::string& expected,
                               const FileSnapshot& before, std::chrono::seconds timeout = std::chrono::seconds(15))
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    do
    {
        std::error_code error;
        if (std::filesystem::exists(path, error) && !error)
        {
            const auto modified = std::filesystem::last_write_time(path, error);
            if (!error && (!before.exists || modified != before.modified))
            {
                std::ifstream file(path, std::ios::binary);
                const std::string content(std::istreambuf_iterator<char>(file), {});
                if (file.is_open() && content.find(expected) != std::string::npos)
                    return true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } while (std::chrono::steady_clock::now() < deadline);
    return false;
}

inline std::string readInput(const Input& input, int argc, char** argv, bool interactive)
{
    std::string value = optionValue(argc, argv, input.option);
    if (!value.empty())
    {
        return value;
    }

    value = envValue(input.env);
    if (!value.empty())
    {
        return value;
    }

    if (!input.defaultValue.empty())
    {
        return input.defaultValue;
    }

    if (interactive)
    {
        std::cout << input.description << " (" << input.option << " / " << input.env << "): ";
        std::getline(std::cin, value);
    }

    return value;
}

inline void printUsage(const char* testName, const std::vector<Input>& inputs)
{
    std::cout << testName << '\n';
    std::cout << "Options communes: --help, --interactive, --execute\n";
    std::cout << "Sans --execute, le test valide seulement la configuration et le packing C2Message.\n\n";

    for (const auto& input : inputs)
    {
        std::cout << "  " << input.option << " ou " << input.env;
        if (input.required)
        {
            std::cout << " (required)";
        }
        if (!input.defaultValue.empty())
        {
            std::cout << " [default: " << input.defaultValue << "]";
        }
        std::cout << "\n    " << input.description << '\n';
    }
}

inline int skipMissing(const char* testName, const std::vector<Input>& missing)
{
    std::cout << testName << " skipped: missing functional test configuration.\n";
    for (const auto& input : missing)
    {
        std::cout << "  missing " << input.option << " or " << input.env << '\n';
    }
    std::cout << "Run with --help for accepted inputs, or --interactive for prompted manual input.\n";
    return skipReturnCode;
}

template <typename Module>
int runModuleScenario(const char* testName, Module& module, std::vector<std::string> command, bool execute)
{
    C2Message message;
    if (module.init(command, message) != 0)
    {
        std::cerr << testName << " init failed:\n" << message.returnvalue() << '\n';
        return 1;
    }

    std::cout << testName << " init OK\n";
    std::cout << "instruction: " << message.instruction() << '\n';

    if (!execute)
    {
        std::cout << "execution skipped; pass --execute to run the module process path.\n";
        return 0;
    }

    C2Message result;
    module.process(message, result);
    if (result.errorCode() > 0)
    {
        std::string error;
        module.errorCodeToMsg(result, error);
        std::cerr << testName << " process failed: " << error << '\n';
        return 1;
    }

    std::cout << result.returnvalue() << '\n';
    return 0;
}

template <typename Module>
int runModuleScenarioIsolated(const char* testName, std::vector<std::string> command, bool execute,
                              const std::string& expectedOutput = {})
{
    Module preparer;
    C2Message prepared;
    if (preparer.init(command, prepared) != 0)
    {
        std::cerr << testName << " init failed:\n" << prepared.returnvalue() << '\n';
        return 1;
    }

    C2Message request = test_helpers::roundTripMessage(prepared);
    if (command.empty() || request.instruction() != command.front())
    {
        std::cerr << testName << " did not prepare the expected instruction.\n";
        return 1;
    }
    if (!execute)
    {
        std::cout << testName << " serialized request OK; execution skipped.\n";
        return 0;
    }

    Module executor;
    C2Message executed;
    executor.process(request, executed);
    C2Message response = test_helpers::roundTripMessage(executed);
    Module receiver;
    std::string error;
    receiver.errorCodeToMsg(response, error);
    if (response.errorCode() != 0 || !error.empty())
    {
        std::cerr << testName << " process failed (code " << response.errorCode() << "): " << error << '\n';
        return 1;
    }
    if (!expectedOutput.empty() && response.returnvalue().find(expectedOutput) == std::string::npos)
    {
        std::cerr << testName << " output did not contain the expected text.\n";
        return 1;
    }
    std::cout << response.returnvalue() << '\n';
    return 0;
}

}
