#include "../../WmiExec.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

using namespace functional_tests;

int main(int argc, char** argv)
{
    const std::vector<Input> inputs = {
        {"--auth", "C2_FUNC_WMI_AUTH", "Authentication mode: no-cred, kerberos, or userpass", false, false, "no-cred"},
        {"--target", "C2_FUNC_WMI_TARGET", "Remote hostname or IP", true},
        {"--command", "C2_FUNC_WMI_COMMAND", "Remote command line to execute", true},
        {"--user", "C2_FUNC_WMI_USER", "Username for userpass mode, optionally DOMAIN\\user", false},
        {"--password", "C2_FUNC_WMI_PASSWORD", "Password for userpass mode", false, true},
        {"--dc", "C2_FUNC_WMI_DC", "Domain controller hint for kerberos mode, optionally DOMAIN\\dc", false},
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsWmiExecFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = hasFlag(argc, argv, "--execute");

#ifndef _WIN32
    if (execute)
    {
        std::cout << "testsWmiExecFunctional skipped: execution is only supported on Windows.\n";
        return skipReturnCode;
    }
#endif

    const std::string auth = readInput(inputs[0], argc, argv, interactive);
    const std::string target = readInput(inputs[1], argc, argv, interactive);
    const std::string commandLine = readInput(inputs[2], argc, argv, interactive);
    const std::string user = readInput(inputs[3], argc, argv, interactive);
    const std::string password = readInput(inputs[4], argc, argv, interactive);
    const std::string dc = readInput(inputs[5], argc, argv, interactive);

    std::vector<Input> missing;
    if (target.empty())
    {
        missing.push_back(inputs[1]);
    }
    if (commandLine.empty())
    {
        missing.push_back(inputs[2]);
    }
    if (auth == "userpass" && user.empty())
    {
        missing.push_back(inputs[3]);
    }
    if (auth == "userpass" && password.empty())
    {
        missing.push_back(inputs[4]);
    }
    if (auth == "kerberos" && dc.empty())
    {
        missing.push_back(inputs[5]);
    }
    if (!missing.empty())
    {
        return skipMissing("testsWmiExecFunctional", missing);
    }

    std::vector<std::string> command = {"wmiExec"};
    if (auth == "userpass")
    {
        command.insert(command.end(), {"-u", user, password, target, commandLine});
    }
    else if (auth == "kerberos")
    {
        command.insert(command.end(), {"-k", dc, target, commandLine});
    }
    else
    {
        command.insert(command.end(), {"-n", target, commandLine});
    }

    return runModuleScenarioIsolated<WmiExec>("testsWmiExecFunctional", command, execute);
}
