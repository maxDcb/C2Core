#include "../../Evasion.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

using namespace functional_tests;

namespace
{
bool requiresValue(const std::string& action)
{
    return action == "Introspection" || action == "ReadMemory" || action == "PatchMemory";
}

bool requiresExtra(const std::string& action)
{
    return action == "ReadMemory" || action == "PatchMemory";
}
}

int main(int argc, char** argv)
{
    const std::vector<Input> inputs = {
        {"--action", "C2_FUNC_EVASION_ACTION", "Evasion action, e.g. CheckHooks, DisableETW, Unhook, AmsiBypass, Introspection, ReadMemory, PatchMemory, RemotePatch", false, false, "CheckHooks"},
        {"--value", "C2_FUNC_EVASION_VALUE", "Primary value for actions such as Introspection, ReadMemory, or PatchMemory", false},
        {"--extra", "C2_FUNC_EVASION_EXTRA", "Secondary value for actions such as ReadMemory size or PatchMemory bytes", false},
        {"--expect", "C2_FUNC_EVASION_EXPECT", "Expected output for actions other than CheckHooks", false},
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsEvasionFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = shouldExecute(argc, argv, "C2_FUNC_EVASION_EXECUTE");

#ifndef _WIN32
    if (execute)
    {
        std::cout << "testsEvasionFunctional skipped: execution is only supported on Windows.\n";
        return skipReturnCode;
    }
#endif

    const std::string action = readInput(inputs[0], argc, argv, interactive);
    const std::string value = readInput(inputs[1], argc, argv, interactive);
    const std::string extra = readInput(inputs[2], argc, argv, interactive);
    const std::string expected = readInput(inputs[3], argc, argv, interactive);

    std::vector<Input> missing;
    if (requiresValue(action) && value.empty())
    {
        missing.push_back(inputs[1]);
    }
    if (requiresExtra(action) && extra.empty())
    {
        missing.push_back(inputs[2]);
    }
    if (execute && action != "CheckHooks" && expected.empty())
        missing.push_back(inputs[3]);
    if (!missing.empty())
    {
        return skipMissing("testsEvasionFunctional", missing);
    }

    std::vector<std::string> command = {"evasion", action};
    if (!value.empty())
    {
        command.push_back(value);
    }
    if (!extra.empty())
    {
        command.push_back(extra);
    }

    Evasion preparer;
    C2Message prepared;
    if (preparer.init(command, prepared) != 0)
    {
        std::cerr << "Evasion request preparation failed.\n";
        return 1;
    }
    const C2Message request = test_helpers::roundTripMessage(prepared);
    if (request.instruction() != "evasion" || request.cmd().empty())
        return 1;
    if (!execute)
        return 0;

    Evasion executor;
    C2Message wireRequest = request;
    C2Message executed;
    executor.process(wireRequest, executed);
    const C2Message response = test_helpers::roundTripMessage(executed);
    Evasion receiver;
    std::string error;
    receiver.errorCodeToMsg(response, error);
    if (response.errorCode() != 0 || !error.empty())
    {
        std::cerr << "Evasion action failed: " << error << '\n';
        return 1;
    }
    if (action == "CheckHooks")
    {
        for (const char* name : {"kernel32.dll", "ntdll.dll", "kernelbase.dll"})
        {
            if (response.returnvalue().find(name) == std::string::npos)
            {
                std::cerr << "CheckHooks output missing " << name << '\n';
                return 1;
            }
        }
    }
    else if (response.returnvalue().find(expected) == std::string::npos)
    {
        std::cerr << "Evasion output did not contain the expected text.\n";
        return 1;
    }
    return 0;
}
