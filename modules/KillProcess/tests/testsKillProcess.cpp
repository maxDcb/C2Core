#include "../KillProcess.hpp"
#include "../../tests/SleepingChild.hpp"
#include "../../tests/TestHelpers.hpp"

#include <string>
#include <vector>

int main(int argc, char** argv)
{
    if (test_helpers::isSleepingChild(argc, argv))
        return 0;

    bool ok = true;
    KillProcess module;
    C2Message request;
    std::vector<std::string> invalid = {"killProcess", "0"};
    ok &= test_helpers::expect(module.init(invalid, request) == -1,
        "init rejects a PID that could target a process group");
    invalid = {"killProcess", "not-a-pid"};
    ok &= test_helpers::expect(module.init(invalid, request) == -1,
        "init rejects a malformed PID");

    test_helpers::SleepingChild child(argv[0]);
    ok &= test_helpers::expect(child.pid > 0, "a test-only child process starts");
    if (child.pid > 0)
    {
        std::vector<std::string> command = {"killProcess", std::to_string(child.pid)};
        C2Message response;
        ok &= test_helpers::expect(module.init(command, request) == 0,
            "init prepares the child PID");
        module.process(request, response);
        ok &= test_helpers::expect(response.instruction() == "killProcess"
            && response.errorCode() == 0 && response.returnvalue() == "Killed.",
            "process reports a successful termination in C2Message");
        ok &= test_helpers::expect(child.waitForTermination(),
            "the test-only child actually terminates");
    }
    return ok ? 0 : 1;
}
