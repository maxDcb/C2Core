#include "../../Remove/Remove.hpp"
#include "../../Run/Run.hpp"
#include "../../Shell/Shell.hpp"
#include "../TestHelpers.hpp"
#include "MessageTestHelpers.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
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

bool hasMessage(ModuleCmd& receiver, int code, const std::string& expected)
{
    C2Message codeOnly;
    codeOnly.set_errorCode(code);
    std::string message = "earlier error";
    receiver.errorCodeToMsg(test_helpers::roundTripMessage(codeOnly), message);
    return test_helpers::expect(message == expected,
        "received code " + std::to_string(code) + " maps without executor state");
}

test_helpers::MessageExchange shellExchange(Shell& preparer, Shell& executor,
    std::vector<std::string> command)
{
    return test_helpers::exchangeMessages(preparer, executor, std::move(command));
}
}

int main()
{
    using test_helpers::expect;
    using test_helpers::roundTripMessage;
    bool ok = expect(hasExport(REMOVE_MODULE_PATH, "RemoveConstructor")
        && hasExport(RUN_MODULE_PATH, "RunConstructor")
        && hasExport(SHELL_MODULE_PATH, "ShellConstructor"),
        "the three shared libraries export their original constructors");

    const fs::path temp = fs::temp_directory_path()
        / ("c2core-command-contract-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(temp);

    Remove removePreparer;
    Remove removeExecutor;
    Remove removeReceiver;
    ok &= expect(removePreparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "remove declares both platforms");
    C2Message invalid;
    std::vector<std::string> incomplete = {"remove"};
    ok &= expect(removePreparer.init(incomplete, invalid) == -1,
        "remove rejects a missing path before transport");
    const fs::path nested = temp / "nested";
    fs::create_directories(nested);
    std::ofstream(nested / "sample.txt") << "sample";
    auto removed = test_helpers::exchangeMessages(removePreparer, removeExecutor,
        {"remove", (nested / "sample.txt").string()});
    ok &= expect(removed.response.instruction() == "remove" && removed.response.errorCode() == 0
        && removed.response.returnvalue() == "Removed." && !fs::exists(nested / "sample.txt"),
        "remove deletes a file with a serialized success response");
    removed = test_helpers::exchangeMessages(removePreparer, removeExecutor,
        {"remove", nested.string()});
    ok &= expect(removed.response.errorCode() == 0 && !fs::exists(nested),
        "remove also deletes a directory");
    C2Message invalidRemoveRequest;
    invalidRemoveRequest.set_instruction("remove");
    C2Message invalidRemoveRaw;
    removeExecutor.process(invalidRemoveRequest, invalidRemoveRaw);
    const C2Message invalidRemove = roundTripMessage(invalidRemoveRaw);
    ok &= expect(invalidRemove.errorCode() == 1 && invalidRemove.returnvalue().empty(),
        "remove returns only an error code for an empty transported path");
    ok &= hasMessage(removeReceiver, 1, "Failed: Could not remove path");
    ok &= hasMessage(removeReceiver, 0, "");
    C2Message noRecurring;
    ok &= expect(removeReceiver.followUp(removed.response) == 0
        && removeExecutor.recurringExec(noRecurring) == 0,
        "remove has no follow-up or recurring work");

    Run runPreparer;
    Run runExecutor;
    Run runReceiver;
    ok &= expect(runPreparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "run declares both platforms");
    incomplete = {"run"};
    ok &= expect(runPreparer.init(incomplete, invalid) == -1,
        "run rejects an empty command before transport");
#ifdef _WIN32
    auto runSuccess = test_helpers::exchangeMessages(runPreparer, runExecutor,
        {"run", "cmd.exe", "/c", "echo", "c2core-run-ok"});
    auto runFailure = test_helpers::exchangeMessages(runPreparer, runExecutor,
        {"run", "cmd.exe", "/c", "exit", "/b", "7"});
#else
    auto runSuccess = test_helpers::exchangeMessages(runPreparer, runExecutor,
        {"run", "printf", "c2core-run-ok"});
    auto runFailure = test_helpers::exchangeMessages(runPreparer, runExecutor,
        {"run", "false"});
#endif
    ok &= expect(runSuccess.response.instruction() == "run"
        && runSuccess.response.errorCode() == 0
        && runSuccess.response.returnvalue().find("c2core-run-ok") != std::string::npos,
        "run transports captured command output with success code zero");
    ok &= expect(runFailure.response.errorCode() == 3
        && runFailure.response.returnvalue().empty(),
        "a nonzero child exit produces a code-only failure");
    ok &= hasMessage(runReceiver, 1, "Process failed to start.");
    ok &= hasMessage(runReceiver, 2, "Could not prepare process output capture.");
    ok &= hasMessage(runReceiver, 3, "Process exited with a non-zero status.");
    ok &= hasMessage(runReceiver, 0, "");
    ok &= expect(runReceiver.followUp(runSuccess.response) == 0
        && runExecutor.recurringExec(noRecurring) == 0,
        "run has no follow-up or recurring work");

    Shell shellPreparer;
    Shell shellExecutor;
    Shell shellReceiver;
    ok &= expect(shellPreparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "shell declares both platforms");
    incomplete.clear();
    ok &= expect(shellPreparer.init(incomplete, invalid) == -1,
        "shell rejects an empty instruction before transport");
    Shell firstCommandExecutor;
    auto firstCommand = shellExchange(shellPreparer, firstCommandExecutor,
        {"shell", "echo", "c2core-first-command"});
    ok &= expect(firstCommand.response.errorCode() == 0
        && firstCommand.response.returnvalue().find("c2core-first-command") != std::string::npos,
        "the first serialized command runs in a newly started shell");
    shellExchange(shellPreparer, firstCommandExecutor, {"shell", "exit"});
    auto shellStarted = shellExchange(shellPreparer, shellExecutor, {"shell"});
    ok &= expect(shellStarted.response.instruction() == "shell"
        && shellStarted.response.errorCode() == 0
        && shellStarted.response.returnvalue() == "shell started",
        "a separate executing instance starts a persistent shell");
#ifdef _WIN32
    auto shellSet = shellExchange(shellPreparer, shellExecutor,
        {"shell", "set", "C2CORE_SHELL_CONTRACT=alpha&", "echo", "state-set"});
    auto shellRead = shellExchange(shellPreparer, shellExecutor,
        {"shell", "echo", "%C2CORE_SHELL_CONTRACT%"});
#else
    auto shellSet = shellExchange(shellPreparer, shellExecutor,
        {"shell", "export", "C2CORE_SHELL_CONTRACT=alpha;", "echo", "state-set"});
    auto shellRead = shellExchange(shellPreparer, shellExecutor,
        {"shell", "printf", "'%s\\n'", "\"$C2CORE_SHELL_CONTRACT\""});
#endif
    ok &= expect(shellSet.response.errorCode() == 0
        && shellSet.response.returnvalue().find("state-set") != std::string::npos,
        "shell executes a command in its persistent session");
    ok &= expect(shellRead.response.errorCode() == 0
        && shellRead.response.returnvalue().find("alpha") != std::string::npos,
        "shell preserves state across serialized requests");
    auto shellStopped = shellExchange(shellPreparer, shellExecutor, {"shell", "exit"});
    ok &= expect(shellStopped.response.errorCode() == 0
        && shellStopped.response.returnvalue() == "shell terminated",
        "shell terminates from a later serialized request");
    auto shellRestarted = shellExchange(shellPreparer, shellExecutor, {"shell"});
    ok &= expect(shellRestarted.response.errorCode() == 0
        && shellRestarted.response.returnvalue() == "shell started",
        "shell can restart after termination");
    shellExchange(shellPreparer, shellExecutor, {"shell", "exit"});
    ok &= hasMessage(shellReceiver, 1, "Failed to start shell.");
    ok &= hasMessage(shellReceiver, 0, "");
    ok &= expect(shellReceiver.followUp(shellStopped.response) == 0
        && shellExecutor.recurringExec(noRecurring) == 0,
        "shell has no follow-up or recurring work");

    fs::remove_all(temp);
    return ok ? 0 : 1;
}
