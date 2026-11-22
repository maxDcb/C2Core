#include "../../KillProcess/KillProcess.hpp"
#include "../../Script/Script.hpp"
#include "../SleepingChild.hpp"
#include "../TestHelpers.hpp"
#include "MessageTestHelpers.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace
{
namespace fs = std::filesystem;

bool hasExport(const char* path, const char* symbol)
{
#ifdef _WIN32
    HMODULE library = LoadLibraryA(path);
    if (!library)
        return false;
    const bool found = GetProcAddress(library, symbol) != nullptr;
    FreeLibrary(library);
#else
    void* library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library)
        return false;
    const bool found = dlsym(library, symbol) != nullptr;
    dlclose(library);
#endif
    return found;
}

bool expectError(ModuleCmd& receiver, int code, const std::string& expected)
{
    C2Message codeOnly;
    codeOnly.set_errorCode(code);
    std::string message = "earlier error";
    receiver.errorCodeToMsg(test_helpers::roundTripMessage(codeOnly), message);
    return test_helpers::expect(message == expected,
        "received code " + std::to_string(code) + " maps without executor state");
}

void writeFile(const fs::path& path, const std::string& content)
{
    std::ofstream output(path, std::ios::binary);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
}
}

int main(int argc, char** argv)
{
    if (test_helpers::isSleepingChild(argc, argv))
        return 0;

    using test_helpers::expect;
    using test_helpers::roundTripMessage;
    bool ok = expect(hasExport(KILLPROCESS_MODULE_PATH, "KillProcessConstructor")
        && hasExport(SCRIPT_MODULE_PATH, "ScriptConstructor"),
        "process module libraries export their original constructors");

    KillProcess killPreparer;
    KillProcess killExecutor;
    KillProcess killReceiver;
    ok &= expect(killPreparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "killProcess declares Linux and Windows support");
    C2Message invalid;
    std::vector<std::string> invalidArgs = {"killProcess", "-1"};
    ok &= expect(killPreparer.init(invalidArgs, invalid) == -1,
        "killProcess rejects a process-group PID");
    invalidArgs = {"killProcess", "12bad"};
    ok &= expect(killPreparer.init(invalidArgs, invalid) == -1,
        "killProcess rejects a partially parsed PID");
    C2Message badRequest;
    badRequest.set_instruction("killProcess");
    badRequest.set_pid(0);
    C2Message transportedBadRequest = roundTripMessage(badRequest);
    C2Message badRaw;
    killExecutor.process(transportedBadRequest, badRaw);
    const C2Message badResponse = roundTripMessage(badRaw);
    ok &= expect(badResponse.errorCode() == 1 && badResponse.returnvalue().empty(),
        "an invalid transported PID produces a code-only failure");
    ok &= expectError(killReceiver, 1, "Failed: Could not kill process");
    ok &= expectError(killReceiver, 0, "");

    test_helpers::SleepingChild child(argv[0]);
    ok &= expect(child.pid > 0, "a test-only child process starts");
    if (child.pid > 0)
    {
        const auto killed = test_helpers::exchangeMessages(killPreparer, killExecutor,
            {"killProcess", std::to_string(child.pid)});
        ok &= expect(killed.request.pid() == child.pid
            && killed.response.instruction() == "killProcess"
            && killed.response.errorCode() == 0
            && killed.response.returnvalue() == "Killed.",
            "a separate executor terminates the serialized test-only PID");
        ok &= expect(child.waitForTermination(), "the test-only child actually exits");
    }
    C2Message noRecurring;
    ok &= expect(killReceiver.followUp(badResponse) == 0
        && killExecutor.recurringExec(noRecurring) == 0,
        "killProcess has default follow-up and recurring hooks");

    const fs::path temp = fs::temp_directory_path()
        / ("c2core-script-contract-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(temp);
    Script scriptPreparer;
    Script scriptExecutor;
    Script scriptReceiver;
    ok &= expect(scriptPreparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "script declares Linux and Windows support");
    invalidArgs = {"script"};
    ok &= expect(scriptPreparer.init(invalidArgs, invalid) == -1,
        "script rejects a missing artifact before transport");
#ifdef _WIN32
    const fs::path successSource = temp / "success.cmd";
    writeFile(successSource, "@echo off\r\necho c2core-script-success\r\n");
    const fs::path failureSource = temp / "failure.cmd";
    writeFile(failureSource, "@echo off\r\nexit /b 7\r\n");
#else
    const fs::path successSource = temp / "success.sh";
    writeFile(successSource, "printf c2core-script-success");
    const fs::path failureSource = temp / "failure.sh";
    writeFile(failureSource, "exit 7");
#endif
    C2Message prepared;
    std::vector<std::string> command = {"script", successSource.string()};
    ok &= expect(scriptPreparer.init(command, prepared) == 0,
        "script loads local artifact bytes into C2Message");
    C2Message request = roundTripMessage(prepared);
    fs::remove(successSource);
    C2Message successRaw;
    scriptExecutor.process(request, successRaw);
    const C2Message success = roundTripMessage(successRaw);
    ok &= expect(success.errorCode() == 0 && success.instruction() == "script"
        && success.returnvalue().find("c2core-script-success") != std::string::npos,
        "script executes only bytes received through the serialized request");
    const auto failure = test_helpers::exchangeMessages(scriptPreparer, scriptExecutor,
        {"script", failureSource.string()});
    ok &= expect(failure.response.errorCode() == 1
        && failure.response.returnvalue().empty(),
        "a nonzero script exit transports only its error code");
    ok &= expectError(scriptReceiver, 1, "Script execution failed.");
#ifdef _WIN32
    const fs::path unsupportedSource = temp / "unsupported.ps1";
    writeFile(unsupportedSource, "Write-Output unsupported\r\n");
    const auto unsupported = test_helpers::exchangeMessages(scriptPreparer, scriptExecutor,
        {"script", unsupportedSource.string()});
    ok &= expect(unsupported.response.errorCode() == 2
        && unsupported.response.returnvalue().empty(),
        "an unsupported Windows script type produces a code-only failure");
#endif
    ok &= expectError(scriptReceiver, 2, "Unsupported script type on Windows. Use .bat or .cmd.");
    ok &= expectError(scriptReceiver, 3, "Failed to create temporary script path.");
    ok &= expectError(scriptReceiver, 4, "Failed to write temporary script.");
    ok &= expectError(scriptReceiver, 5, "CreatePipe failed.");
    ok &= expectError(scriptReceiver, 6, "SetHandleInformation failed.");
    ok &= expectError(scriptReceiver, 7, "CreateProcess failed.");
    ok &= expectError(scriptReceiver, 0, "");
    ok &= expect(scriptReceiver.followUp(success) == 0
        && scriptExecutor.recurringExec(noRecurring) == 0,
        "script has default follow-up and recurring hooks");

    fs::remove_all(temp);
    return ok ? 0 : 1;
}
