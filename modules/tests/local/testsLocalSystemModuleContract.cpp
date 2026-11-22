#include "../../IpConfig/IpConfig.hpp"
#include "../../Netstat/Netstat.hpp"
#include "../../ListProcesses/ListProcesses.hpp"
#include "../TestHelpers.hpp"
#include "MessageTestHelpers.hpp"

#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

bool checkDynamicExport(const char* path, const char* symbol)
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

template <typename Module>
bool checkModule(const std::string& command, const std::string& errorText)
{
    using test_helpers::expect;
    using test_helpers::exchangeMessages;
    using test_helpers::roundTripMessage;

    std::unique_ptr<Module> preparer(new Module());
    Module executor;
    Module receiver;
    bool ok = expect(preparer->osCompatibility() == (OS_LINUX | OS_WINDOWS),
        command + " declares Linux and Windows support");

    C2Message invalid;
    std::vector<std::string> invalidArgs;
    ok &= expect(preparer->init(invalidArgs, invalid) == -1,
        command + " rejects missing arguments");
    invalidArgs = {command, "unexpected"};
    ok &= expect(preparer->init(invalidArgs, invalid) == -1,
        command + " rejects extra arguments");

    const auto exchange = exchangeMessages(*preparer, executor, {command});
    ok &= expect(exchange.request.instruction() == command &&
        exchange.response.instruction() == command && exchange.response.errorCode() == 0,
        command + " carries its instruction and success code through both messages");
    if (command != "netstat")
        ok &= expect(!exchange.response.returnvalue().empty(),
            command + " returns an enumeration result");

    std::string message;
    receiver.errorCodeToMsg(exchange.response, message);
    ok &= expect(message.empty(), command + " does not report an error on success");

    C2Message errorOnly;
    errorOnly.set_errorCode(1);
    receiver.errorCodeToMsg(roundTripMessage(errorOnly), message);
    ok &= expect(message == errorText,
        command + " translates a received error code without local diagnostic state");

    ok &= expect(receiver.followUp(exchange.response) == 0,
        command + " accepts the default follow-up hook");
    C2Message recurring;
    ok &= expect(receiver.recurringExec(recurring) == 0,
        command + " has no recurring result by default");
    return ok;
}

int main()
{
    using test_helpers::expect;
    bool ok = true;
    std::unique_ptr<IpConfig> ip(IpConfigConstructor());
    std::unique_ptr<Netstat> net(NetstatConstructor());
    std::unique_ptr<ListProcesses> processes(ListProcessesConstructor());
    ok &= expect(ip != nullptr && net != nullptr && processes != nullptr,
        "all three modules expose their original constructor");
    ok &= expect(checkDynamicExport(IPCONFIG_MODULE_PATH, "IpConfigConstructor"),
        "ipConfig shared library exports its constructor");
    ok &= expect(checkDynamicExport(NETSTAT_MODULE_PATH, "NetstatConstructor"),
        "netstat shared library exports its constructor");
    ok &= expect(checkDynamicExport(LISTPROCESSES_MODULE_PATH, "ListProcessesConstructor"),
        "ps shared library exports its constructor");

    ok &= checkModule<IpConfig>("ipConfig", "Failed to enumerate network interfaces.");
    ok &= checkModule<Netstat>("netstat", "Failed to enumerate network connections.");
    ok &= checkModule<ListProcesses>("ps", "Failed to enumerate processes.");

    return ok ? 0 : 1;
}
