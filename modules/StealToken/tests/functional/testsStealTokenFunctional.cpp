#include "../../StealToken.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

using namespace functional_tests;

int main(int argc, char** argv)
{
    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsStealTokenFunctional", {});
        std::cout << "The target is this test process only.\n";
        return 0;
    }
    const bool execute = shouldExecute(argc, argv, "C2_FUNC_STEALTOKEN_EXECUTE");
#ifndef _WIN32
    if (execute)
        return skipReturnCode;
#endif
#ifdef _WIN32
    const int pid = static_cast<int>(GetCurrentProcessId());
#else
    const int pid = 1;
#endif
    const int result = runModuleScenarioIsolated<StealToken>(
        "testsStealTokenFunctional", {"stealToken", std::to_string(pid)}, execute,
        execute ? "Token impersonated successfully" : "");
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
        std::cerr << "StealToken did not install an impersonation token on the thread.\n";
        return 1;
    }
#endif
    return 0;
}
