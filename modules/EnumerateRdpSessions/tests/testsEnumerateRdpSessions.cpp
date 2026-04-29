#include "../EnumerateRdpSessions.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <memory>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        EnumerateRdpSessions module;
        std::vector<std::string> cmd = {"enumerateRdpSessions"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "init should accept local enumeration");
        ok &= expect(message.instruction() == "enumerateRdpSessions", "instruction should be set");

        const auto fields = splitPackedFields(message.cmd());
        ok &= expect(fields.size() == 1, "packed RDP parameters should contain one field");
        if (fields.size() == 1)
        {
            ok &= expect(fields[0].empty(), "default server should be empty for local enumeration");
        }
    }

    {
        EnumerateRdpSessions module;
        std::vector<std::string> cmd = {"enumerateRdpSessions", "-s", "server01"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "init should accept explicit server");
        const auto fields = splitPackedFields(message.cmd());
        ok &= expect(fields.size() == 1, "packed explicit RDP parameters should contain one field");
        if (fields.size() == 1)
        {
            ok &= expect(fields[0] == "server01", "server should be packed");
        }
    }

    {
        EnumerateRdpSessions module;
        std::vector<std::string> cmd = {"enumerateRdpSessions", "-s"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing -s value should be rejected");
    }

    {
        EnumerateRdpSessions module;
        C2Message ret;
        ret.set_errorCode(EnumerateRdpSessions::ERROR_OPEN_SERVER);
        ret.set_returnvalue("open failed");
        std::string error;

        ok &= expect(module.errorCodeToMsg(ret, error) == 0, "errorCodeToMsg should return success");
        ok &= expect(error == "open failed", "errorCodeToMsg should expose process error text");
    }

    return ok ? 0 : 1;
}
