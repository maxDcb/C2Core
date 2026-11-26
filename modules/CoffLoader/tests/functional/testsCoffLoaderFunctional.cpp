#include "../../CoffLoader.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

using namespace functional_tests;

int main(int argc, char** argv)
{
    const std::vector<Input> inputs = {
        {"--object", "C2_FUNC_COFF_OBJECT", "COFF object file", false,
#ifdef C2_COFF_FIXTURE
            false, C2_COFF_FIXTURE},
#else
            false, ""},
#endif
        {"--entry", "C2_FUNC_COFF_ENTRY", "COFF entrypoint", false, false, "go"},
        {"--expect", "C2_FUNC_COFF_EXPECT", "Expected BOF output", false, false, "C2CORE_COFF_OK"},
    };
    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsCoffLoaderFunctional", inputs);
        return 0;
    }
    const bool execute = shouldExecute(argc, argv, "C2_FUNC_COFF_EXECUTE");
#ifndef _WIN32
    if (execute)
        return skipReturnCode;
#endif
    const bool interactive = hasFlag(argc, argv, "--interactive");
    const std::string object = readInput(inputs[0], argc, argv, interactive);
    const std::string entry = readInput(inputs[1], argc, argv, interactive);
    const std::string expected = readInput(inputs[2], argc, argv, interactive);
    if (object.empty() || entry.empty() || (execute && expected.empty()))
        return skipMissing("testsCoffLoaderFunctional", inputs);
    return runModuleScenarioIsolated<CoffLoader>(
        "testsCoffLoaderFunctional", {"coffLoader", object, entry}, execute, expected);
}
