#include "../../Rev2self.hpp"
#include "../../../StealToken/StealToken.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

using namespace functional_tests;

int main(int argc, char** argv)
{
    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsRev2selfFunctional", {});
        std::cout << "The test impersonates its own process token before reverting.\n";
        return 0;
    }
    const bool execute = shouldExecute(argc, argv, "C2_FUNC_REV2SELF_EXECUTE");
#ifndef _WIN32
    if (execute)
        return skipReturnCode;
    return 0;
#else
    Rev2self preparer;
    C2Message prepared;
    std::vector<std::string> command = {"rev2self"};
    if (preparer.init(command, prepared) != 0)
        return 1;
    C2Message request = test_helpers::roundTripMessage(prepared);
    if (request.instruction() != "rev2self")
        return 1;
    if (!execute)
        return 0;

    const int pid = static_cast<int>(GetCurrentProcessId());
    if (runModuleScenarioIsolated<StealToken>("rev2self setup",
            {"stealToken", std::to_string(pid)}, true, "Token impersonated successfully") != 0)
        return 1;
    HANDLE token = nullptr;
    const BOOL hadToken = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token);
    if (token != nullptr) CloseHandle(token);
    if (!hadToken)
        return 1;

    Rev2self executor;
    C2Message executed;
    executor.process(request, executed);
    const C2Message response = test_helpers::roundTripMessage(executed);
    Rev2self receiver;
    std::string error;
    receiver.errorCodeToMsg(response, error);
    token = nullptr;
    const BOOL stillHasToken = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token);
    if (token != nullptr) CloseHandle(token);
    const DWORD tokenError = GetLastError();
    RevertToSelf();
    if (response.errorCode() != 0 || !error.empty() ||
        response.returnvalue() != "Reverted to self.\n" ||
        stillHasToken || tokenError != ERROR_NO_TOKEN)
    {
        std::cerr << "Rev2self did not clear the impersonation token.\n";
        return 1;
    }
    return 0;
#endif
}
