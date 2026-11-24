#pragma once

#include "local/MessageTestHelpers.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
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
int runModuleScenarioIsolated(const char* testName, std::vector<std::string> command, bool execute)
{
    Module preparer;
    C2Message prepared;
    if (preparer.init(command, prepared) != 0)
    {
        std::cerr << testName << " init failed:\n" << prepared.returnvalue() << '\n';
        return 1;
    }

    C2Message request = test_helpers::roundTripMessage(prepared);
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
    std::cout << response.returnvalue() << '\n';
    return 0;
}

}
