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
        {"--verify-file", "C2_FUNC_PSEXEC_VERIFY_FILE", "Local or UNC path to the service's marker file", false},
        {"--expect", "C2_FUNC_PSEXEC_EXPECT", "Expected marker content", false, false, "Hello"},
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsPsExecFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = shouldExecute(argc, argv, "C2_FUNC_PSEXEC_EXECUTE");

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
    const std::string verifyFile = readInput(inputs[5], argc, argv, interactive);
    const std::string expected = readInput(inputs[6], argc, argv, interactive);

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
    if (execute && verifyFile.empty())
        missing.push_back(inputs[5]);
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

    const FileSnapshot before = execute ? snapshotFile(verifyFile) : FileSnapshot{};
    const int result = runModuleScenarioIsolated<PsExec>("testsPsExecFunctional", command, execute);
    if (result != 0 || !execute)
        return result;
    if (!waitForFileContent(verifyFile, expected, before))
    {
        std::cerr << "PsExec service did not create a fresh marker with expected content.\n";
        return 1;
    }
    return 0;
}
