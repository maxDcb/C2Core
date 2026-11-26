#include "../../Chisel.hpp"
#include "../../../tests/FunctionalTestHelpers.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

using namespace functional_tests;

int main(int argc, char** argv)
{
    if (hasFlag(argc, argv, "--help"))
    {
        printUsage("testsChiselFunctional", {});
        std::cout << "The stop scenario terminates only a process created by this test.\n";
        return 0;
    }
    const bool execute = shouldExecute(argc, argv, "C2_FUNC_CHISEL_EXECUTE");
#ifndef _WIN32
    if (execute)
        return skipReturnCode;
    return 0;
#else
    if (!execute)
    {
        Chisel preparer;
        C2Message prepared;
        std::vector<std::string> command = {"chisel", "stop", "1234"};
        return preparer.init(command, prepared) == 0 &&
            test_helpers::roundTripMessage(prepared).pid() == 1234 ? 0 : 1;
    }

    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    std::string commandLine = "powershell.exe -NoProfile -Command Start-Sleep -Seconds 30";
    if (!CreateProcessA(nullptr, commandLine.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child))
    {
        std::cerr << "Could not create the test-owned process.\n";
        return 1;
    }
    CloseHandle(child.hThread);
    Chisel preparer;
    C2Message prepared;
    std::vector<std::string> command = {"chisel", "stop", std::to_string(child.dwProcessId)};
    bool passed = preparer.init(command, prepared) == 0;
    if (passed)
    {
        C2Message request = test_helpers::roundTripMessage(prepared);
        Chisel executor;
        C2Message executed;
        executor.process(request, executed);
        const C2Message response = test_helpers::roundTripMessage(executed);
        Chisel receiver;
        std::string error;
        receiver.errorCodeToMsg(response, error);
        passed = response.errorCode() == 0 && error.empty() &&
            response.returnvalue().find("Chisel stoped") != std::string::npos &&
            WaitForSingleObject(child.hProcess, 5000) == WAIT_OBJECT_0;
    }
    if (!passed)
        TerminateProcess(child.hProcess, 9);
    CloseHandle(child.hProcess);
    if (!passed)
        std::cerr << "Chisel did not stop its test-owned process.\n";
    return passed ? 0 : 1;
#endif
}
