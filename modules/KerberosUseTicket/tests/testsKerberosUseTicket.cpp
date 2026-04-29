#include "../KerberosUseTicket.hpp"
#include "../../tests/TestHelpers.hpp"

#include <filesystem>
#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        KerberosUseTicket module;
        std::vector<std::string> cmd = {"kerberosUseTicket"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing ticket file should be rejected");
    }

    {
        KerberosUseTicket module;
        std::vector<std::string> cmd = {"kerberosUseTicket", "missing.kirbi"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "nonexistent ticket file should be rejected");
        ok &= expect(message.returnvalue().find("Couldn't open file") != std::string::npos, "nonexistent ticket error should mention open failure");
    }

    {
        const auto ticket = writeTempFile("c2core_ticket.kirbi", "ticket-bytes");
        KerberosUseTicket module;
        std::vector<std::string> cmd = {"kerberosUseTicket", ticket.string()};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "existing ticket file should be accepted");
        ok &= expect(message.instruction() == "kerberosUseTicket", "instruction should be set");
        ok &= expect(message.inputfile() == ticket.string(), "input file should be packed");
        ok &= expect(message.data() == "ticket-bytes", "ticket bytes should be packed");
        std::filesystem::remove(ticket);
    }

    return ok ? 0 : 1;
}
