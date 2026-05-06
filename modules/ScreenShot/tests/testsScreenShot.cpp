#include "../ScreenShot.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <string>
#include <vector>

using namespace test_helpers;

namespace
{
bool hasBmpHeader(const std::string& data)
{
    return data.size() >= 2 && data[0] == 'B' && data[1] == 'M';
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

        ok &= expect(module.recurringExec(recurring) == 1, "recurringExec should report no recurring work yet");
    }

    {
        ScreenShot module;
        C2Message ret;

        ok &= expect(module.followUp(ret) == 0, "followUp should accept an empty response");
        ret.set_data("not-a-bmp");
        ok &= expect(module.followUp(ret) == 0, "followUp should accept response data");
    }

    {
        ScreenShot module;
        std::vector<std::string> cmd = {"screenShot"};
        C2Message message;
        C2Message ret;

        ok &= expect(module.init(cmd, message) == 0, "process setup should initialize");
        message.set_outputfile("generated-screenshot.bmp");
        ok &= expect(module.process(message, ret) == 0, "process should return success");
        ok &= expect(ret.instruction() == "screenShot", "process should preserve instruction");
        ok &= expect(ret.outputfile() == "generated-screenshot.bmp", "process should preserve generated artifact output path");
        ok &= expect(ret.args() == "0", "process should mark screenshot as the first artifact chunk");

#ifdef _WIN32
        ok &= expect(ret.returnvalue() == "Success", "Windows process should report Success");
        if (!ret.data().empty())
        {
            ok &= expect(hasBmpHeader(ret.data()), "Windows screenshot data should have a BMP header when data is captured");
        }
#else
        ok &= expect(ret.returnvalue().empty(), "non-Windows process should not report screenshot output");
        ok &= expect(ret.data().empty(), "non-Windows process should not capture data");
#endif
    }

    {
        ScreenShot module;
        C2Message ret;
        ret.set_errorCode(1);
        std::string error = "unchanged";

        ok &= expect(module.errorCodeToMsg(ret, error) == 0, "errorCodeToMsg should return success");
#ifdef BUILD_TEAMSERVER
        ok &= expect(error == "Failed: Couldn't open file", "errorCodeToMsg should expose open-file error in teamserver builds");
#else
        ok &= expect(error == "unchanged", "errorCodeToMsg should leave text unchanged outside teamserver builds");
#endif
    }

    return ok ? 0 : 1;
}
