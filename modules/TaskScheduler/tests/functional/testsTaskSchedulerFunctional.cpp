#include "../../TaskScheduler.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

using namespace functional_tests;

int main(int argc, char** argv)
{
    const std::vector<Input> inputs = {
        {"--command", "C2_FUNC_TASK_COMMAND", "Program to run through the scheduler", true},
        {"--args", "C2_FUNC_TASK_ARGS", "Program arguments", false},
        {"--server", "C2_FUNC_TASK_SERVER", "Remote scheduler server; omit for local", false},
        {"--task", "C2_FUNC_TASK_NAME", "Task name", false, false, "C2FunctionalTask"},
        {"--user", "C2_FUNC_TASK_USER", "Username, optionally DOMAIN\\user", false},
        {"--password", "C2_FUNC_TASK_PASSWORD", "Password", false, true},
        {"--verify-file", "C2_FUNC_TASK_VERIFY_FILE", "Local or UNC path written by the scheduled action", false},
        {"--expect", "C2_FUNC_TASK_EXPECT", "Expected content of the new file", false},
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsTaskSchedulerFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = shouldExecute(argc, argv, "C2_FUNC_TASK_EXECUTE");

    const std::string remoteCommand = readInput(inputs[0], argc, argv, interactive);
    const std::string args = readInput(inputs[1], argc, argv, interactive);
    const std::string server = readInput(inputs[2], argc, argv, interactive);
    const std::string task = readInput(inputs[3], argc, argv, interactive);
    const std::string user = readInput(inputs[4], argc, argv, interactive);
    const std::string password = readInput(inputs[5], argc, argv, interactive);
    const std::string verifyFile = readInput(inputs[6], argc, argv, interactive);
    const std::string expected = readInput(inputs[7], argc, argv, interactive);

    std::vector<Input> missing;
    if (remoteCommand.empty())
    {
        missing.push_back(inputs[0]);
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
        return skipMissing("testsTaskSchedulerFunctional", missing);
    }

    std::vector<std::string> command = {"taskScheduler", "-t", task, "-c", remoteCommand};
    if (!execute)
    {
        command.push_back("--no-run");
    }
    if (!args.empty())
    {
        command.insert(command.end(), {"-a", args});
    }
    if (!server.empty())
    {
        command.insert(command.end(), {"-s", server});
    }
    if (!user.empty())
    {
        command.insert(command.end(), {"-u", user, "-p", password});
    }

    const FileSnapshot before = execute ? snapshotFile(verifyFile) : FileSnapshot{};
    const int result = runModuleScenarioIsolated<TaskScheduler>("testsTaskSchedulerFunctional", command, execute);
    if (result != 0 || !execute)
        return result;
    if (!waitForFileContent(verifyFile, expected, before))
    {
        std::cerr << "Task Scheduler did not create a fresh file with expected content.\n";
        return 1;
    }
    return 0;
}
