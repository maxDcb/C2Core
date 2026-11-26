#include "../../DcomExec.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

using namespace functional_tests;

int main(int argc, char** argv)
{
    const std::vector<Input> inputs = {
        {"--host", "C2_FUNC_DCOM_HOST", "Remote hostname or IP", true},
        {"--command", "C2_FUNC_DCOM_COMMAND", "Program to execute remotely", true},
        {"--args", "C2_FUNC_DCOM_ARGS", "Arguments for the remote program", false},
        {"--workdir", "C2_FUNC_DCOM_WORKDIR", "Remote working directory", false},
        {"--spn", "C2_FUNC_DCOM_SPN", "Kerberos SPN, e.g. HOST/server.domain", false},
        {"--user", "C2_FUNC_DCOM_USER", "Username, optionally DOMAIN\\user", false},
        {"--password", "C2_FUNC_DCOM_PASSWORD", "Password", false, true},
        {"--verify-file", "C2_FUNC_DCOM_VERIFY_FILE", "Local or UNC path written by the remote command", false},
        {"--expect", "C2_FUNC_DCOM_EXPECT", "Expected content of the new file", false},
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsDcomExecFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = shouldExecute(argc, argv, "C2_FUNC_DCOM_EXECUTE");

#ifndef _WIN32
    if (execute)
        return skipReturnCode;
#endif

    const std::string host = readInput(inputs[0], argc, argv, interactive);
    const std::string remoteCommand = readInput(inputs[1], argc, argv, interactive);
    const std::string args = readInput(inputs[2], argc, argv, interactive);
    const std::string workdir = readInput(inputs[3], argc, argv, interactive);
    const std::string spn = readInput(inputs[4], argc, argv, interactive);
    const std::string user = readInput(inputs[5], argc, argv, interactive);
    const std::string password = readInput(inputs[6], argc, argv, interactive);
    const std::string verifyFile = readInput(inputs[7], argc, argv, interactive);
    const std::string expected = readInput(inputs[8], argc, argv, interactive);

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
        missing.push_back(inputs[6]);
    }
    if (execute && verifyFile.empty())
        missing.push_back(inputs[7]);
    if (execute && expected.empty())
        missing.push_back(inputs[8]);
    if (!missing.empty())
    {
        return skipMissing("testsDcomExecFunctional", missing);
    }

    std::vector<std::string> command = {"dcomExec", "-h", host, "-c", remoteCommand};
    if (!args.empty())
    {
        command.insert(command.end(), {"-a", args});
    }
    if (!workdir.empty())
    {
        command.insert(command.end(), {"-w", workdir});
    }
    if (!spn.empty())
    {
        command.insert(command.end(), {"-k", spn});
    }
    if (!user.empty())
    {
        command.insert(command.end(), {"-u", user, "-p", password});
    }
    else
    {
        command.push_back("-n");
    }

    const FileSnapshot before = execute ? snapshotFile(verifyFile) : FileSnapshot{};
    const int result = runModuleScenarioIsolated<DcomExec>("testsDcomExecFunctional", command, execute);
    if (result != 0 || !execute)
        return result;
    if (!waitForFileContent(verifyFile, expected, before))
    {
        std::cerr << "DCOM did not create a fresh file with expected content.\n";
        return 1;
    }
    return 0;
}
