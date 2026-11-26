#include "../../MakeToken.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

using namespace functional_tests;

int main(int argc, char** argv)
{
    const std::vector<Input> inputs = {
        {"--user", "C2_FUNC_MAKETOKEN_USER", "Lab account, optionally DOMAIN\\user", true},
        {"--password", "C2_FUNC_MAKETOKEN_PASSWORD", "Lab account password", true, true},
    };
    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsMakeTokenFunctional", inputs);
        return 0;
    }
    const bool execute = shouldExecute(argc, argv, "C2_FUNC_MAKETOKEN_EXECUTE");
#ifndef _WIN32
    if (execute)
        return skipReturnCode;
#endif
    const bool interactive = hasFlag(argc, argv, "--interactive");
    const std::string user = readInput(inputs[0], argc, argv, interactive);
    const std::string password = readInput(inputs[1], argc, argv, interactive);
    std::vector<Input> missing;
    if (user.empty()) missing.push_back(inputs[0]);
    if (password.empty()) missing.push_back(inputs[1]);
    if (!missing.empty())
        return skipMissing("testsMakeTokenFunctional", missing);

    const int result = runModuleScenarioIsolated<MakeToken>(
        "testsMakeTokenFunctional", {"makeToken", user, password}, execute,
        execute ? "token impersonated successfully" : "");
    if (result != 0 || !execute)
        return result;
#ifdef _WIN32
    HANDLE token = nullptr;
    const BOOL opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token);
    TOKEN_TYPE type = TokenPrimary;
    DWORD bytes = 0;
    const BOOL queried = opened && GetTokenInformation(token, TokenType, &type, sizeof(type), &bytes);
    if (token != nullptr) CloseHandle(token);
    RevertToSelf();
    if (!queried || type != TokenImpersonation)
    {
        std::cerr << "MakeToken did not install an impersonation token on the thread.\n";
        return 1;
    }
#endif
    return 0;
}
