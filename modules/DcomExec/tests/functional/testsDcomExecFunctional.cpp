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
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsDcomExecFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = hasFlag(argc, argv, "--execute");

    const std::string host = readInput(inputs[0], argc, argv, interactive);
    const std::string remoteCommand = readInput(inputs[1], argc, argv, interactive);
    const std::string args = readInput(inputs[2], argc, argv, interactive);
    const std::string workdir = readInput(inputs[3], argc, argv, interactive);
    const std::string spn = readInput(inputs[4], argc, argv, interactive);
    const std::string user = readInput(inputs[5], argc, argv, interactive);
    const std::string password = readInput(inputs[6], argc, argv, interactive);

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

    return runModuleScenarioIsolated<DcomExec>("testsDcomExecFunctional", command, execute);
}
