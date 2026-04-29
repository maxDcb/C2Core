#include "../PsExec.hpp"
#include "../../tests/TestHelpers.hpp"

#include <filesystem>
#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        const auto service = writeTempFile("c2core_service.exe", "service-bytes");
        PsExec module;
        std::vector<std::string> cmd = {"psExec", "-u", "DOMAIN\\alice", "secret", "server01", service.string()};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "credential PsExec form should be accepted");
        ok &= expect(message.instruction() == "psExec", "instruction should be set");
        const auto fields = splitPackedFields(message.cmd());
        ok &= expect(fields.size() == 4, "packed PsExec credential parameters should contain four fields");
        if (fields.size() == 4)
        {
            ok &= expect(fields[0] == "DOMAIN", "domain should be packed");
            ok &= expect(fields[1] == "alice", "username should be packed");
            ok &= expect(fields[2] == "secret", "password should be packed");
            ok &= expect(fields[3] == "server01", "target should be packed");
        }
        ok &= expect(message.data() == "service-bytes", "service bytes should be packed");
        std::filesystem::remove(service);
    }

    {
        PsExec module;
        std::vector<std::string> cmd = {"psExec", "-n", "server01", "missing.exe"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing service file should be rejected");
        ok &= expect(message.returnvalue().find("Couldn't open file") != std::string::npos, "missing service file should explain the error");
    }

    return ok ? 0 : 1;
}
