#include "../ScreenShot.hpp"
#include "../../tests/TestHelpers.hpp"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

using namespace test_helpers;

namespace
{
constexpr std::size_t ChunkSize = 1 * 1024 * 1024;

bool hasPngHeader(const std::string& data)
{
    const unsigned char expected[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    return data.size() >= sizeof(expected)
        && std::equal(
            expected,
            expected + sizeof(expected),
            data.begin(),
            [](unsigned char lhs, char rhs)
            {
                return lhs == static_cast<unsigned char>(rhs);
            });
}
}

int main()
{
    bool ok = true;

    {
        ScreenShot module;
        std::vector<std::string> cmd;
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "init should reject an empty command");
    }

    {
        ScreenShot module;
        std::vector<std::string> cmd = {"screenShot"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "init should accept screenshot command");
        ok &= expect(message.instruction() == "screenShot", "instruction should be set");
        ok &= expect(message.cmd().empty(), "init should not pack command arguments");
        ok &= expect(message.data().empty(), "init should not pack data");
    }

    {
        ScreenShot module;
        std::vector<std::string> cmd = {"screenShot", "ignored", "tokens"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "init should tolerate extra tokens");
        ok &= expect(message.instruction() == "screenShot", "extra tokens should not change instruction");
        ok &= expect(message.cmd().empty(), "extra tokens should not be packed");
    }

    {
        ScreenShot module;
        C2Message recurring;

        ok &= expect(module.recurringExec(recurring) == 0, "recurringExec should report no recurring work when no screenshot is pending");
    }

    {
        ScreenShot module;
        C2Message ret;

        ok &= expect(module.followUp(ret) == 0, "followUp should accept an empty response");
        ret.set_errorCode(0);
        ret.set_outputfile("generated-screenshot.png");
        ret.set_data("not-a-png");
        ok &= expect(module.followUp(ret) == 0, "followUp should accept response data");
    }

    {
        ScreenShot module;
        std::vector<std::string> cmd = {"screenShot"};
        C2Message message;
        C2Message ret;
        const std::string sample = std::string("\x89PNG\r\n\x1a\n", 8) + "synthetic";

        ok &= expect(module.init(cmd, message) == 0, "process setup should initialize");
        message.set_outputfile("generated-screenshot.png");
        message.set_data(sample);
        module.process(message, ret);
        ok &= expect(ret.errorCode() == 0, "synthetic process should put success status in the response");
        ok &= expect(!ret.instruction().empty(), "process should return a screenshot instruction");
        ok &= expect(ret.outputfile() == "generated-screenshot.png", "process should preserve generated artifact output path");
        ok &= expect(ret.args() == "0", "process should mark screenshot as the first artifact chunk");
        ok &= expect(ret.returnvalue() == "Success", "synthetic process should complete a single chunk");
        ok &= expect(hasPngHeader(ret.data()), "synthetic screenshot data should retain its PNG header");
    }

#ifndef _WIN32
    {
        ScreenShot module;
        C2Message message;
        C2Message ret;
        message.set_instruction("screenShot");
        module.process(message, ret);
        ok &= expect(ret.errorCode() == 3 && ret.returnvalue().empty() && ret.data().empty(),
            "Linux reports unsupported capture through a code-only response");
    }
#endif

#if defined(C2CORE_BUILD_TESTS)
    {
        ScreenShot module;
        C2Message message;
        C2Message firstChunk;
        C2Message finalChunk;
        const std::string payload(ChunkSize + 3, 'A');

        message.set_instruction("screenShot");
        message.set_uuid("shot-0001");
        message.set_outputfile("generated-screenshot.png");
        message.set_data(payload);

        ok &= expect(module.process(message, firstChunk) == 0, "test payload process should return success");
        ok &= expect(firstChunk.uuid() == "shot-0001", "first chunk should preserve task uuid");
        ok &= expect(firstChunk.outputfile() == "generated-screenshot.png", "first chunk should preserve output file");
        ok &= expect(firstChunk.args() == "0", "first chunk should be marked as initial artifact data");
        ok &= expect(firstChunk.data().size() == ChunkSize, "first chunk should use the screenshot chunk size");
        ok &= expect(firstChunk.errorCode() == 0, "first chunk should carry success status");
        ok &= expect(firstChunk.returnvalue().find("/") != std::string::npos, "first chunk should report transfer progress");

        ok &= expect(module.recurringExec(finalChunk) == 1, "recurringExec should emit the remaining screenshot chunk");
        ok &= expect(finalChunk.uuid() == "shot-0001", "final chunk should preserve task uuid");
        ok &= expect(finalChunk.outputfile() == "generated-screenshot.png", "final chunk should preserve output file");
        ok &= expect(finalChunk.args() == "1", "final chunk should be marked as a continuation artifact chunk");
        ok &= expect(finalChunk.data().size() == 3, "final chunk should contain the remaining screenshot bytes");
        ok &= expect(finalChunk.errorCode() == 0, "final chunk should carry success status");
        ok &= expect(finalChunk.returnvalue() == "Success", "final chunk should complete the screenshot transfer");

        C2Message done;
        ok &= expect(module.recurringExec(done) == 0, "recurringExec should stop after the final screenshot chunk");
    }
#endif

    {
        ScreenShot module;
        C2Message ret;
        ret.set_errorCode(1);
        std::string error = "unchanged";

        ok &= expect(module.errorCodeToMsg(ret, error) == 0, "errorCodeToMsg should return success");
        ok &= expect(error == "Failed: Couldn't open file", "errorCodeToMsg should expose open-file error in teamserver builds");
        ret.set_errorCode(2);
        error.clear();
        module.errorCodeToMsg(ret, error);
        ok &= expect(error == "Failed: screen capture returned no data", "capture failure has a stable message");
        ret.set_errorCode(3);
        error.clear();
        module.errorCodeToMsg(ret, error);
        ok &= expect(error == "Failed: screen capture is unavailable on this platform", "unsupported capture has a stable message");
    }

    return ok ? 0 : 1;
}
