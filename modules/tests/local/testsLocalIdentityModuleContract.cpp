#include "../../GetEnv/GetEnv.hpp"
#include "../../Whoami/Whoami.hpp"
#include "../../HostContext/HostContext.hpp"
#include "../TestHelpers.hpp"
#include "MessageTestHelpers.hpp"

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

int main()
{
    using test_helpers::expect;
    using test_helpers::exchangeMessages;

    constexpr char markerName[] = "C2CORE_LOCAL_TEST_MARKER";
    constexpr char markerValue[] = "contract-observed";
    const char* previousValue = std::getenv(markerName);
    const bool hadPreviousValue = previousValue != nullptr;
    const std::string previous = hadPreviousValue ? previousValue : "";
#ifdef _WIN32
    if (_putenv_s(markerName, markerValue) != 0)
        return 1;
#else
    if (setenv(markerName, markerValue, 1) != 0)
        return 1;
#endif

    GetEnv envPreparer;
    GetEnv envExecutor;
    GetEnv envReceiver;
    bool ok = expect(envPreparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "getEnv declares Linux and Windows support");
    std::vector<std::string> invalidArgs;
    C2Message invalid;
    ok &= expect(envPreparer.init(invalidArgs, invalid) == -1,
        "getEnv rejects an empty argument vector");
    const auto env = exchangeMessages(envPreparer, envExecutor, {"getEnv"});
    ok &= expect(env.request.instruction() == "getEnv" && env.response.instruction() == "getEnv"
        && env.response.errorCode() == 0,
        "getEnv carries the instruction and success code through both messages");
    ok &= expect(env.response.returnvalue().find(std::string(markerName) + "=" + markerValue) != std::string::npos,
        "getEnv includes the controlled environment variable");
    C2Message errorCodeOnly;
    errorCodeOnly.set_errorCode(1);
    std::string error;
    envReceiver.errorCodeToMsg(errorCodeOnly, error);
    ok &= expect(error == "Failed: Could not retrieve environment",
        "getEnv translates a received error code");

    Whoami whoPreparer;
    Whoami whoExecutor;
    Whoami whoReceiver;
    ok &= expect(whoPreparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "whoami declares Linux and Windows support");
    invalidArgs = {"whoami", "unexpected"};
    ok &= expect(whoPreparer.init(invalidArgs, invalid) == -1,
        "whoami rejects extra arguments");
    const auto who = exchangeMessages(whoPreparer, whoExecutor, {"whoami"});
    ok &= expect(who.request.instruction() == "whoami" && who.response.instruction() == "whoami"
        && who.response.errorCode() == 0 && who.response.returnvalue().find("User: ") != std::string::npos,
        "whoami reports the current user in the received response");
    error.clear();
    whoReceiver.errorCodeToMsg(errorCodeOnly, error);
    ok &= expect(error == "Failed: Could not retrieve user information",
        "whoami translates a received error code");

    std::unique_ptr<HostContext> contextPreparer(HostContextConstructor());
    HostContext contextExecutor;
    HostContext contextReceiver;
    ok &= expect(contextPreparer != nullptr && contextPreparer->osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "HostContext exposes its constructor and declares both platforms");
    if (contextPreparer)
    {
        const auto context = exchangeMessages(*contextPreparer, contextExecutor, {"hostContext"});
        ok &= expect(context.request.instruction() == "hostContext"
            && context.response.instruction() == "hostContext"
            && context.response.errorCode() == 0
            && context.response.returnvalue().find("Hostname: ") != std::string::npos,
            "HostContext carries host information through both messages");
        error.clear();
        contextReceiver.errorCodeToMsg(errorCodeOnly, error);
        ok &= expect(error == "Failed to collect host identity and OS information.",
            "HostContext translates a received error code");
    }

#ifdef _WIN32
    _putenv_s(markerName, hadPreviousValue ? previous.c_str() : "");
#else
    if (hadPreviousValue)
        setenv(markerName, previous.c_str(), 1);
    else
        unsetenv(markerName);
#endif
    return ok ? 0 : 1;
}
