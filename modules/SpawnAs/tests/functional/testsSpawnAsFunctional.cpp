#include "../../SpawnAs.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

using namespace functional_tests;

namespace
{
    bool isTruthy(const std::string& value)
    {
        return value == "1" || value == "true" || value == "TRUE" || value == "yes" || value == "YES";
    }
}

int main(int argc, char** argv)
{
    const std::vector<Input> inputs = {
        {"--user", "C2_FUNC_SPAWNAS_USER", "Username to impersonate, optionally DOMAIN\\user or user@domain", true},
        {"--password", "C2_FUNC_SPAWNAS_PASSWORD", "Password for the target user", true, true},
        {"--command", "C2_FUNC_SPAWNAS_COMMAND", "Command line to spawn as the target user", true},
        {"--domain", "C2_FUNC_SPAWNAS_DOMAIN", "Optional domain override passed with -d", false},
        {"--logon-type", "C2_FUNC_SPAWNAS_LOGON_TYPE", "Logon type (2 or 9)", false, false, "2"},
        {"--profile", "C2_FUNC_SPAWNAS_PROFILE", "Profile mode: with-profile or no-profile", false, false, "with-profile"},
        {"--show-window", "C2_FUNC_SPAWNAS_SHOW_WINDOW", "Show the spawned window (1/0)", false, false, "0"},
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsSpawnAsFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = hasFlag(argc, argv, "--execute");

#ifndef _WIN32
    if (execute)
    {
        std::cout << "testsSpawnAsFunctional skipped: execution is only supported on Windows.\n";
        return skipReturnCode;
    }
#endif

    const std::string user = readInput(inputs[0], argc, argv, interactive);
    const std::string password = readInput(inputs[1], argc, argv, interactive);
    const std::string commandLine = readInput(inputs[2], argc, argv, interactive);
    const std::string domain = readInput(inputs[3], argc, argv, interactive);
    const std::string logonType = readInput(inputs[4], argc, argv, interactive);
    const std::string profileMode = readInput(inputs[5], argc, argv, interactive);
    const std::string showWindow = readInput(inputs[6], argc, argv, interactive);

    std::vector<Input> missing;
    if (user.empty())
    {
        missing.push_back(inputs[0]);
    }
    if (password.empty())
    {
        missing.push_back(inputs[1]);
    }
    if (commandLine.empty())
    {
        missing.push_back(inputs[2]);
    }
    if (!missing.empty())
    {
        return skipMissing("testsSpawnAsFunctional", missing);
    }

    std::vector<std::string> command = {"spawnAs"};
    if (!domain.empty())
    {
        command.insert(command.end(), {"-d", domain});
    }
    if (logonType == "9")
    {
        command.push_back("--netonly");
    }
    else if (!logonType.empty() && logonType != "2")
    {
        command.insert(command.end(), {"--logon-type", logonType});
    }

    if (profileMode == "no-profile")
    {
        command.push_back("--no-profile");
    }
    else
    {
        command.push_back("--with-profile");
    }

    if (isTruthy(showWindow))
    {
        command.push_back("--show-window");
    }

    command.push_back(user);
    command.push_back(password);
    command.push_back("--");
    command.push_back(commandLine);

    return runModuleScenarioIsolated<SpawnAs>("testsSpawnAsFunctional", command, execute);
}
