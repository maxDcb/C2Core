#include "../../EnumerateRdpSessions.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

using namespace functional_tests;

int main(int argc, char** argv)
{
    const std::vector<Input> inputs = {
        {"--server", "C2_FUNC_RDP_SERVER", "Remote RDP server; omit for local session enumeration", false},
        {"--expect-user", "C2_FUNC_RDP_EXPECT_USER", "Username expected in the session listing", false},
    };

    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsEnumerateRdpSessionsFunctional", inputs);
        return 0;
    }

    const bool interactive = hasFlag(argc, argv, "--interactive");
    const bool execute = shouldExecute(argc, argv, "C2_FUNC_RDP_EXECUTE");
    const std::string server = readInput(inputs[0], argc, argv, interactive);
    const std::string expectedUser = readInput(inputs[1], argc, argv, interactive);

    std::vector<std::string> command = {"enumerateRdpSessions"};
    if (!server.empty())
    {
        command.insert(command.end(), {"-s", server});
    }

    EnumerateRdpSessions preparer;
    C2Message prepared;
    if (preparer.init(command, prepared) != 0)
        return 1;
    C2Message request = test_helpers::roundTripMessage(prepared);
    if (request.instruction() != "enumerateRdpSessions")
        return 1;
    if (!execute)
        return 0;
#ifndef _WIN32
    std::cout << "RDP execution requires Windows.\n";
    return skipReturnCode;
#else
    EnumerateRdpSessions executor;
    EnumerateRdpSessions receiver;
    C2Message raw;
    executor.process(request, raw);
    const C2Message response = test_helpers::roundTripMessage(raw);
    std::string error;
    receiver.errorCodeToMsg(response, error);
    const std::string& output = response.returnvalue();
    const bool validListing = output.find("UserName") != std::string::npos
        && output.find("SessionID") != std::string::npos
        && output.find("State") != std::string::npos
        && (output.find("No sessions found.") != std::string::npos
            || output.find('\n', output.find('\n') + 1) != std::string::npos);
    const bool ok = response.instruction() == request.instruction()
        && response.errorCode() == 0 && error.empty() && validListing
        && (expectedUser.empty() || output.find(expectedUser) != std::string::npos);
    if (!ok)
        std::cerr << "RDP listing failed validation (code " << response.errorCode() << "): " << error << '\n';
    return ok ? 0 : 1;
#endif
}
