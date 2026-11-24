#include "../../ScreenShot/ScreenShot.hpp"
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

bool hasExportedConstructor()
{
#ifdef _WIN32
    HMODULE library = LoadLibraryA(SCREENSHOT_MODULE_PATH);
    if (!library)
        return false;
    const bool found = GetProcAddress(library, "ScreenShotConstructor") != nullptr;
    FreeLibrary(library);
#else
    void* library = dlopen(SCREENSHOT_MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
    if (!library)
        return false;
    const bool found = dlsym(library, "ScreenShotConstructor") != nullptr;
    dlclose(library);
#endif
    return found;
}

int main()
{
    using test_helpers::expect;
    using test_helpers::roundTripMessage;
    namespace fs = std::filesystem;
    constexpr std::size_t chunkSize = 1024 * 1024;

    ScreenShot preparer;
    ScreenShot executor;
    ScreenShot receiver;
    bool ok = expect(hasExportedConstructor(),
        "screenShot shared library exports its constructor");
    ok &= expect(preparer.osCompatibility() == OS_WINDOWS,
        "screenShot declares Windows-only capture support");

    std::vector<std::string> command = {"screenShot"};
    C2Message prepared;
    ok &= expect(preparer.init(command, prepared) == 0,
        "screenShot prepares a request");
    prepared.set_uuid("shot-contract-001");
    const std::string sample(chunkSize + 3, 'S');
    prepared.set_data(sample);
    C2Message request = roundTripMessage(prepared);

    C2Message first;
    executor.process(request, first);
    const C2Message firstReceived = roundTripMessage(first);
    ok &= expect(firstReceived.errorCode() == 0 && firstReceived.data() == sample.substr(0, chunkSize),
        "process sends the first synthetic chunk with success status");
    ok &= expect(firstReceived.uuid() == "shot-contract-001"
        && firstReceived.outputfile().empty() && firstReceived.args() == "0",
        "the first chunk keeps task and artifact metadata");

    C2Message final;
    ok &= expect(executor.recurringExec(final) == 1,
        "recurringExec emits the remaining chunk");
    const C2Message finalReceived = roundTripMessage(final);
    ok &= expect(finalReceived.errorCode() == 0 && finalReceived.data() == sample.substr(chunkSize)
        && finalReceived.args() == "1" && finalReceived.returnvalue() == "Success",
        "the final chunk completes the serialized transfer");
    ok &= expect(finalReceived.uuid() == firstReceived.uuid()
        && finalReceived.outputfile() == firstReceived.outputfile(),
        "recurringExec preserves task and artifact metadata");
    C2Message noMore;
    ok &= expect(executor.recurringExec(noMore) == 0,
        "recurringExec has no result after the final chunk");

    C2Message codeOnly;
    codeOnly.set_errorCode(2);
    std::string error;
    receiver.errorCodeToMsg(roundTripMessage(codeOnly), error);
    ok &= expect(error == "Failed: screen capture returned no data",
        "capture failure is rendered from the received code alone");
    codeOnly.set_errorCode(3);
    error.clear();
    receiver.errorCodeToMsg(roundTripMessage(codeOnly), error);
    ok &= expect(error == "Failed: screen capture is unavailable on this platform",
        "unsupported capture is rendered from the received code alone");
    codeOnly.set_errorCode(0);
    receiver.errorCodeToMsg(roundTripMessage(codeOnly), error);
    ok &= expect(error.empty(), "a successful response clears an earlier error message");

#ifndef _WIN32
    C2Message unsupportedRequest;
    unsupportedRequest.set_instruction("screenShot");
    C2Message unsupported;
    executor.process(unsupportedRequest, unsupported);
    const C2Message unsupportedReceived = roundTripMessage(unsupported);
    ok &= expect(unsupportedReceived.errorCode() == 3 && unsupportedReceived.data().empty()
        && unsupportedReceived.returnvalue().empty(),
        "Linux reports unsupported capture without data or an error string");
#endif

    const fs::path original = fs::current_path();
    const fs::path temp = fs::temp_directory_path()
        / ("c2core-shot-contract-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(temp);
    fs::current_path(temp);
    C2Message failedFollowUp;
    failedFollowUp.set_errorCode(2);
    failedFollowUp.set_data("ignored-failure-data");
    receiver.followUp(roundTripMessage(failedFollowUp));
    ok &= expect(fs::directory_iterator(temp) == fs::directory_iterator{},
        "followUp ignores data in an error response");
    ScreenShot firstReceiver;
    ScreenShot secondReceiver;
    ok &= expect(firstReceiver.followUp(firstReceived) == 0,
        "a receiving instance writes the initial chunk");
    ok &= expect(secondReceiver.followUp(finalReceived) == 0,
        "another receiving instance appends the final chunk");
    const fs::path assembled = temp / "screenShotshot-contract-001.png";
    ok &= expect(fs::exists(assembled), "followUp stores the assembled artifact");
    if (fs::exists(assembled))
    {
        std::ifstream file(assembled, std::ios::binary);
        const std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        ok &= expect(content == sample, "followUp combines all received chunks exactly");
    }
    fs::current_path(original);
    fs::remove_all(temp);

    return ok ? 0 : 1;
}
