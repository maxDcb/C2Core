#include "../../PsExec.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

using namespace functional_tests;

namespace
{
std::string defaultServicePath()
{
#ifdef C2_PSEXEC_TEST_SERVICE
    return C2_PSEXEC_TEST_SERVICE;
#else
    return {};
#endif
}
}

int main(int argc, char** argv)
{
    const std::vector<Input> inputs = {
        {"--auth", "C2_FUNC_PSEXEC_AUTH", "Authentication mode: no-cred, kerberos, or userpass", false, false, "no-cred"},
        {"--target", "C2_FUNC_PSEXEC_TARGET", "Remote hostname or IP", true},
        {"--service", "C2_FUNC_PSEXEC_SERVICE", "Windows service executable to deploy", false, false, defaultServicePath()},
        {"--user", "C2_FUNC_PSEXEC_USER", "Username for userpass mode, optionally DOMAIN\\user", false},
        {"--password", "C2_FUNC_PSEXEC_PASSWORD", "Password for userpass mode", false, true},
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsPsExecFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = hasFlag(argc, argv, "--execute");

#ifndef _WIN32
    if (execute)
    {
        std::cout << "testsPsExecFunctional skipped: execution is only supported on Windows.\n";
        return skipReturnCode;
    }
#endif

    const std::string auth = readInput(inputs[0], argc, argv, interactive);
    const std::string target = readInput(inputs[1], argc, argv, interactive);
    const std::string service = readInput(inputs[2], argc, argv, interactive);
    const std::string user = readInput(inputs[3], argc, argv, interactive);
    const std::string password = readInput(inputs[4], argc, argv, interactive);

    std::vector<Input> missing;
    if (target.empty())
    {
        missing.push_back(inputs[1]);
    }
    if (service.empty())
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
    if (!missing.empty())
    {
        return skipMissing("testsPsExecFunctional", missing);
    }

    std::vector<std::string> command = {"psExec"};
    if (auth == "userpass")
    {
        command.insert(command.end(), {"-u", user, password, target, service});
    }
    else if (auth == "kerberos")
    {
        command.insert(command.end(), {"-k", target, service});
    }
    else
    {
        command.insert(command.end(), {"-n", target, service});
    }

    return runModuleScenarioIsolated<PsExec>("testsPsExecFunctional", command, execute);
}
