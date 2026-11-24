#include "../../CimExec.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

using namespace functional_tests;

int main(int argc, char** argv)
{
    const std::vector<Input> inputs = {
        {"--host", "C2_FUNC_CIM_HOST", "Remote hostname or IP", true},
        {"--command", "C2_FUNC_CIM_COMMAND", "Program to execute remotely", true},
        {"--args", "C2_FUNC_CIM_ARGS", "Arguments for the remote program", false},
        {"--namespace", "C2_FUNC_CIM_NAMESPACE", "CIM namespace", false, false, "root/cimv2"},
        {"--user", "C2_FUNC_CIM_USER", "Username, optionally DOMAIN\\user", false},
        {"--password", "C2_FUNC_CIM_PASSWORD", "Password", false, true},
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsCimExecFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = hasFlag(argc, argv, "--execute");

    const std::string host = readInput(inputs[0], argc, argv, interactive);
    const std::string remoteCommand = readInput(inputs[1], argc, argv, interactive);
    const std::string args = readInput(inputs[2], argc, argv, interactive);
    const std::string namespaceName = readInput(inputs[3], argc, argv, interactive);
    const std::string user = readInput(inputs[4], argc, argv, interactive);
    const std::string password = readInput(inputs[5], argc, argv, interactive);

    std::vector<Input> missing;
    if (host.empty())
    {
        missing.push_back(inputs[0]);
    }
    if (remoteCommand.empty())
    {
        missing.push_back(inputs[1]);
    }
    if (!user.empty() && password.empty())
    {
        missing.push_back(inputs[5]);
    }
    if (!missing.empty())
    {
        return skipMissing("testsCimExecFunctional", missing);
    }

    std::vector<std::string> command = {"cimExec", "-h", host, "-n", namespaceName, "-c", remoteCommand};
    if (!args.empty())
    {
        command.insert(command.end(), {"-a", args});
    }
    if (!user.empty())
    {
        command.insert(command.end(), {"-u", user, "-p", password});
    }

    return runModuleScenarioIsolated<CimExec>("testsCimExecFunctional", command, execute);
}
