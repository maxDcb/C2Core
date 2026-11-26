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
        {"--verify-file", "C2_FUNC_CIM_VERIFY_FILE", "Local or UNC path written by the remote command", false},
        {"--expect", "C2_FUNC_CIM_EXPECT", "Expected content of the new file", false},
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsCimExecFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = shouldExecute(argc, argv, "C2_FUNC_CIM_EXECUTE");

#ifndef _WIN32
    if (execute)
        return skipReturnCode;
#endif

    const std::string host = readInput(inputs[0], argc, argv, interactive);
    const std::string remoteCommand = readInput(inputs[1], argc, argv, interactive);
    const std::string args = readInput(inputs[2], argc, argv, interactive);
    const std::string namespaceName = readInput(inputs[3], argc, argv, interactive);
    const std::string user = readInput(inputs[4], argc, argv, interactive);
    const std::string password = readInput(inputs[5], argc, argv, interactive);
    const std::string verifyFile = readInput(inputs[6], argc, argv, interactive);
    const std::string expected = readInput(inputs[7], argc, argv, interactive);

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
    if (execute && verifyFile.empty())
        missing.push_back(inputs[6]);
    if (execute && expected.empty())
        missing.push_back(inputs[7]);
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

    const FileSnapshot before = execute ? snapshotFile(verifyFile) : FileSnapshot{};
    const int result = runModuleScenarioIsolated<CimExec>("testsCimExecFunctional", command, execute);
    if (result != 0 || !execute)
        return result;
    if (!waitForFileContent(verifyFile, expected, before))
    {
        std::cerr << "CIM did not create a fresh file with expected content.\n";
        return 1;
    }
    return 0;
}
